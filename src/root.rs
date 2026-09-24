//! Every filesystem access in unbidden goes through a Root.
//!
//! Two reasons, both from the threat model. A scan root that is a mounted
//! image must never resolve a symlink out into the analyst's own filesystem,
//! and a directory an unprivileged user can write to must never be walked by
//! following links blindly. Root owns both policies so no collector has to
//! remember them, and no collector may name an absolute path directly.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags};

/// Default ceiling on a single file read. Hostile input is assumed; nothing
/// under a path an attacker may control is read unbounded.
pub const READ_CAP: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub size: u64,
    pub mtime: Option<SystemTime>,
    /// When the inode last changed. Unlike mtime, nothing short of setting
    /// the system clock moves it to a chosen value, so it can order two
    /// writes an attacker would rather were not ordered.
    pub ctime: Option<SystemTime>,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub is_file: bool,
}

impl Meta {
    /// Permission bits only, as the human table and the JSON report them.
    pub fn perms(&self) -> u32 {
        self.mode & 0o7777
    }

    pub fn world_writable(&self) -> bool {
        self.mode & 0o002 != 0
    }
}

pub struct DirEnt {
    pub name: OsString,
    pub is_dir: bool,
    pub is_symlink: bool,
}

pub struct Root {
    fd: OwnedFd,
    base: PathBuf,
    live: bool,
    confined: bool,
    /// Home directories, once discovered. A symlink inside one of these whose
    /// target leaves it is not followed — see `escaping_link`.
    homes: std::sync::OnceLock<Vec<PathBuf>>,
}

impl Root {
    /// The running system. Live-only interfaces are available.
    pub fn live() -> io::Result<Root> {
        Root::open_root("/", true)
    }

    /// A mounted image or chroot. Live-only interfaces are unavailable and
    /// resolution is confined to the root by the kernel.
    pub fn at(path: impl AsRef<Path>) -> io::Result<Root> {
        Root::open_root(path.as_ref(), false)
    }

    fn open_root(path: impl AsRef<Path>, live: bool) -> io::Result<Root> {
        let path = path.as_ref();
        let fd = rustix::fs::open(path, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?;
        let confined = probe_openat2(&fd);
        Ok(Root {
            fd,
            base: path.to_path_buf(),
            live,
            confined,
            homes: std::sync::OnceLock::new(),
        })
    }

    /// True on a running system. Collectors reading /proc, /sys or D-Bus must
    /// check this and degrade to their on-disk sources rather than omitting
    /// entries.
    pub fn is_live(&self) -> bool {
        self.live
    }

    /// The path an operator would type to reach `rel` — what lands in
    /// `Entry::source`. Absolute on a live root, root-prefixed offline.
    pub fn abs(&self, rel: impl AsRef<Path>) -> PathBuf {
        let rel = strip_leading_slash(rel.as_ref());
        if self.base == Path::new("/") {
            Path::new("/").join(rel)
        } else {
            self.base.join(rel)
        }
    }

    fn open_raw(&self, rel: &Path, flags: OFlags) -> io::Result<OwnedFd> {
        let rel = strip_leading_slash(rel);
        // openat2 rejects an empty path; the root itself is the dir fd.
        let rel = if rel.as_os_str().is_empty() { Path::new(".") } else { rel };
        let flags = flags | OFlags::CLOEXEC;
        if self.confined {
            let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS;
            Ok(rustix::fs::openat2(&self.fd, rel, flags, Mode::empty(), resolve)?)
        } else if self.live {
            // The root is `/`, where an absolute link and a `..` past the top
            // land exactly where RESOLVE_IN_ROOT would put them.
            Ok(rustix::fs::openat(&self.fd, rel, flags, Mode::empty())?)
        } else {
            // A mounted image on a kernel without openat2 (RHEL 7, anything
            // before 5.6): resolve every link by hand inside the root, then
            // open the result one component at a time refusing links, so a
            // link swapped in after the resolution fails rather than escapes.
            let resolved = self.resolve(rel)?;
            self.open_resolved(&resolved, flags)
        }
    }

    /// Where `rel` leads once every symlink along it has been followed, in
    /// root coordinates, resolved the way `RESOLVE_IN_ROOT` resolves: an
    /// absolute target restarts at the scan root and `..` stops there.
    ///
    /// Every prefix that is consulted has already been proven free of links,
    /// so no lookup here can be redirected out of the root. The answer is a
    /// description of the tree at one moment; anything that acts on it opens
    /// it with `open_resolved`, which refuses links outright.
    pub fn resolve(&self, rel: &Path) -> io::Result<PathBuf> {
        let mut done: Vec<OsString> = Vec::new();
        let mut todo: std::collections::VecDeque<OsString> = normal_components(rel).collect();
        let mut hops = 0;
        while let Some(c) = todo.pop_front() {
            if c == ".." {
                done.pop();
                continue;
            }
            done.push(c);
            let here: PathBuf = done.iter().collect();
            let st = rustix::fs::statat(&self.fd, &here, AtFlags::SYMLINK_NOFOLLOW)?;
            if !meta_of(&st).is_symlink {
                continue;
            }
            // The kernel's own ceiling on links followed in one lookup.
            hops += 1;
            if hops > 40 {
                return Err(io::Error::from_raw_os_error(rustix::io::Errno::LOOP.raw_os_error()));
            }
            let target = rustix::fs::readlinkat(&self.fd, &here, Vec::new())?;
            let target = Path::new(OsStr::from_bytes(target.as_bytes()));
            done.pop();
            if target.is_absolute() {
                done.clear();
            }
            for c in normal_components(target).collect::<Vec<_>>().into_iter().rev() {
                todo.push_front(c);
            }
        }
        Ok(done.iter().collect())
    }

    /// Opens a path `resolve` produced, following no link at all. Anything
    /// that became a link since the resolution is refused with ELOOP.
    fn open_resolved(&self, resolved: &Path, flags: OFlags) -> io::Result<OwnedFd> {
        let flags = flags | OFlags::CLOEXEC;
        if self.confined {
            let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
            let rel = if resolved.as_os_str().is_empty() { Path::new(".") } else { resolved };
            return Ok(rustix::fs::openat2(&self.fd, rel, flags, Mode::empty(), resolve)?);
        }
        let parts: Vec<&OsStr> = resolved.iter().collect();
        let Some((last, dirs)) = parts.split_last() else {
            return Ok(rustix::fs::openat(&self.fd, ".", flags, Mode::empty())?);
        };
        let mut dir = rustix::fs::openat(&self.fd, ".", OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())?;
        for part in dirs {
            let next = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            dir = rustix::fs::openat(&dir, *part, next, Mode::empty())?;
        }
        let fd = rustix::fs::openat(&dir, *last, flags | OFlags::NOFOLLOW, Mode::empty())?;
        // O_PATH with O_NOFOLLOW hands back the link itself rather than
        // failing, so a descriptor of that kind is checked by hand.
        if flags.contains(OFlags::PATH) {
            let st = rustix::fs::fstat(&fd)?;
            if meta_of(&st).is_symlink {
                return Err(io::Error::from_raw_os_error(rustix::io::Errno::LOOP.raw_os_error()));
            }
        }
        Ok(fd)
    }

    /// Declares the home directories found on this root. Set once, before
    /// any collector runs, so the symlink rule below applies to every read.
    pub fn set_homes(&self, homes: Vec<PathBuf>) {
        let _ = self.homes.set(homes);
    }

    pub fn homes(&self) -> &[PathBuf] {
        self.homes.get().map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Whether a path sits inside one of the declared homes.
    pub fn in_home(&self, rel: &Path) -> bool {
        let here = self.rel(&self.abs(rel));
        self.homes().iter().any(|h| here.starts_with(self.rel(h)))
    }

    /// A path in someone's home that, once its links are followed, leads out
    /// of that home. Returns where it leads.
    ///
    /// Links within one home are ordinary — every dotfile manager makes them,
    /// and following them is how the real file gets scanned. A link that
    /// leaves is the confused-deputy case: the account that can write the
    /// link need not be able to read what it points at, but this process
    /// can, and whatever it reads is printed in a report. `~/.bashrc ->
    /// /etc/shadow` would put password hashes in the JSON.
    ///
    /// The whole chain is followed, not the first hop: `../../etc/shadow`,
    /// a link to a second link, and a linked directory partway down the path
    /// all leave the home just as surely as an absolute target does.
    ///
    /// The check lives here rather than in a collector because a collector
    /// that reaches past its own helper would otherwise silently opt out.
    pub fn escaping_link(&self, rel: &Path) -> Option<PathBuf> {
        self.home_confinement(rel)?.ok()?.err()
    }

    /// For a path under a home: either the path it resolves to inside that
    /// home or, as the inner error, where it leads instead. A path that cannot
    /// be resolved at all carries the resolution's error, so the caller refuses
    /// it rather than falling back to an open that follows links.
    fn home_confinement(&self, rel: &Path) -> Option<io::Result<Result<PathBuf, PathBuf>>> {
        let homes = self.homes.get()?;
        // Homes are recorded as they sit inside the root; every path here is
        // compared in the same coordinates so an offline root lines up.
        let here = self.rel(&self.abs(rel));
        let home = homes
            .iter()
            .map(|h| self.rel(h))
            .filter(|h| here.starts_with(h))
            .max_by_key(|h| h.as_os_str().len())?;
        // The home itself may be a link (/home/carol -> /srv/carol); what the
        // path must stay inside is where the home really is.
        let confined = self.resolve(&home).and_then(|real_home| {
            let resolved = self.resolve(&here)?;
            Ok(if resolved.starts_with(&real_home) { Ok(resolved) } else { Err(Path::new("/").join(resolved)) })
        });
        Some(confined)
    }

    pub fn open(&self, rel: impl AsRef<Path>) -> io::Result<File> {
        let rel = rel.as_ref();
        match self.home_confinement(rel) {
            Some(Err(e)) => Err(e),
            Some(Ok(Err(target))) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} leads out of its owner's home to {}; recorded as a link, not followed",
                    rel.display(),
                    target.display()
                ),
            )),
            // Opened as resolved, refusing every link, so a link swapped in
            // between the check and the open fails instead of escaping.
            Some(Ok(Ok(resolved))) => Ok(File::from(self.open_resolved(&resolved, OFlags::RDONLY)?)),
            None => Ok(File::from(self.open_raw(rel, OFlags::RDONLY)?)),
        }
    }

    /// Reads at most `cap` bytes. The returned flag says the file was longer,
    /// which collectors record rather than hide.
    pub fn read_capped(&self, rel: impl AsRef<Path>, cap: usize) -> io::Result<(Vec<u8>, bool)> {
        let file = self.open(rel)?;
        read_capped_from(file, cap)
    }

    pub fn read(&self, rel: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        Ok(self.read_capped(rel, READ_CAP)?.0)
    }

    /// Metadata of the link itself, never its target.
    pub fn stat(&self, rel: impl AsRef<Path>) -> io::Result<Meta> {
        self.statat(rel.as_ref(), AtFlags::SYMLINK_NOFOLLOW)
    }

    /// Metadata after resolving symlinks, confined to the root.
    pub fn stat_follow(&self, rel: impl AsRef<Path>) -> io::Result<Meta> {
        self.statat(rel.as_ref(), AtFlags::empty())
    }

    fn statat(&self, rel: &Path, at: AtFlags) -> io::Result<Meta> {
        let rel = strip_leading_slash(rel);
        let rel = if rel.as_os_str().is_empty() { Path::new(".") } else { rel };
        // statat cannot express RESOLVE_IN_ROOT, so resolution goes through
        // an openat2 handle. For a no-follow stat that means opening the
        // PARENT under confinement and stating the final name there: the
        // final component must not be followed, but everything leading to it
        // still has to stay inside the root.
        // Only a live root without openat2 may hand the kernel a path whole:
        // its root is `/`, so there is nowhere for a link to escape to.
        let st = match (self.confined || !self.live, at.contains(AtFlags::SYMLINK_NOFOLLOW)) {
            (true, false) => {
                let fd = self.open_raw(rel, OFlags::PATH)?;
                rustix::fs::statat(&fd, "", AtFlags::EMPTY_PATH)?
            }
            (true, true) => match (rel.parent(), rel.file_name()) {
                (Some(parent), Some(name)) if !name.is_empty() => {
                    let dir = self.open_raw(parent, OFlags::PATH | OFlags::DIRECTORY)?;
                    rustix::fs::statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW)?
                }
                _ => rustix::fs::statat(&self.fd, rel, at)?,
            },
            (false, _) => rustix::fs::statat(&self.fd, rel, at)?,
        };
        Ok(meta_of(&st))
    }

    pub fn exists(&self, rel: impl AsRef<Path>) -> bool {
        self.stat(rel).is_ok()
    }

    pub fn read_link(&self, rel: impl AsRef<Path>) -> io::Result<PathBuf> {
        let rel = strip_leading_slash(rel.as_ref());
        // The final component is the link being read and is not followed, but
        // the directories leading to it are, and they must stay in the root.
        let target = match (rel.parent(), rel.file_name()) {
            (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
                let dir = self.open_raw(parent, OFlags::PATH | OFlags::DIRECTORY)?;
                rustix::fs::readlinkat(&dir, name, Vec::new())?
            }
            _ => rustix::fs::readlinkat(&self.fd, rel, Vec::new())?,
        };
        Ok(PathBuf::from(OsStr::from_bytes(target.as_bytes()).to_os_string()))
    }

    /// Directory listing, links reported but never followed. Missing
    /// directories are an empty listing rather than an error: most search
    /// paths are absent on most hosts, and that is not a collector failure.
    pub fn read_dir(&self, rel: impl AsRef<Path>) -> io::Result<Vec<DirEnt>> {
        let fd = self.open_raw(rel.as_ref(), OFlags::RDONLY | OFlags::DIRECTORY)?;
        let mut out = Vec::new();
        for ent in Dir::read_from(&fd)? {
            let ent = ent?;
            let name = ent.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let name = OsStr::from_bytes(name).to_os_string();
            let (mut is_dir, is_symlink) = match ent.file_type() {
                FileType::Directory => (true, false),
                FileType::Symlink => (false, true),
                FileType::Unknown => (false, false),
                _ => (false, false),
            };
            if ent.file_type() == FileType::Unknown {
                // Some filesystems do not fill d_type; ask the kernel.
                if let Ok(st) = rustix::fs::statat(&fd, ent.file_name(), AtFlags::SYMLINK_NOFOLLOW) {
                    is_dir = meta_of(&st).is_dir;
                }
            }
            out.push(DirEnt { name, is_dir, is_symlink });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// As `read_dir`, but an absent directory yields nothing and a permission
    /// error is returned so the caller can record a partial collector.
    pub fn read_dir_optional(&self, rel: impl AsRef<Path>) -> io::Result<Vec<DirEnt>> {
        match self.read_dir(rel) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            other => other,
        }
    }

    /// Device and inode of a directory, so a search path that is two names for
    /// one directory — merged-usr's /lib and /usr/lib — is walked once.
    pub fn dir_identity(&self, rel: impl AsRef<Path>) -> io::Result<(u64, u64)> {
        let rel = strip_leading_slash(rel.as_ref());
        let rel = if rel.as_os_str().is_empty() { Path::new(".") } else { rel };
        let fd = self.open_raw(rel, OFlags::PATH | OFlags::DIRECTORY)?;
        let st = rustix::fs::statat(&fd, "", AtFlags::EMPTY_PATH)?;
        Ok((st.st_dev as u64, st.st_ino as u64))
    }
}

fn meta_of(st: &rustix::fs::Stat) -> Meta {
    let mode = st.st_mode as u32;
    let at = |secs: i64, nanos: i64| {
        let whole = if secs >= 0 {
            UNIX_EPOCH + Duration::from_secs(secs as u64)
        } else {
            UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
        };
        Some(whole + Duration::from_nanos(nanos.clamp(0, 999_999_999) as u64))
    };
    let mtime = at(st.st_mtime as i64, 0);
    let ctime = at(st.st_ctime as i64, st.st_ctime_nsec as i64);
    Meta {
        uid: st.st_uid as u32,
        gid: st.st_gid as u32,
        mode,
        size: st.st_size as u64,
        mtime,
        ctime,
        is_dir: mode & rustix::fs::FileType::Directory.as_raw_mode() as u32 != 0
            && mode & 0o170000 == rustix::fs::FileType::Directory.as_raw_mode() as u32,
        is_symlink: mode & 0o170000 == rustix::fs::FileType::Symlink.as_raw_mode() as u32,
        is_file: mode & 0o170000 == rustix::fs::FileType::RegularFile.as_raw_mode() as u32,
    }
}

pub fn read_capped_from(mut file: File, cap: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    let read = (&mut file).take(cap as u64 + 1).read_to_end(&mut buf)?;
    let truncated = read > cap;
    buf.truncate(cap);
    Ok((buf, truncated))
}

/// The named components of a path, `..` kept and `.` and `/` dropped.
fn normal_components(p: &Path) -> impl Iterator<Item = OsString> + '_ {
    p.components().filter_map(|c| match c {
        Component::Normal(n) => Some(n.to_os_string()),
        Component::ParentDir => Some(OsString::from("..")),
        _ => None,
    })
}

fn strip_leading_slash(p: &Path) -> &Path {
    let mut p = p;
    while let Ok(rest) = p.strip_prefix("/") {
        p = rest;
    }
    p
}

/// Does this kernel have openat2 with RESOLVE_IN_ROOT? Linux 5.6 and later do.
fn probe_openat2(fd: &OwnedFd) -> bool {
    rustix::fs::openat2(
        fd,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
    )
    .is_ok()
}

/// Directories that are dot-prefixed by convention rather than to hide
/// anything. Without this list every per-user autostart entry, every
/// authorized_keys and every shell profile reports as hidden, which is the
/// opposite of useful.
const CONVENTIONAL_DOT_DIRS: [&[u8]; 6] =
    [b".config", b".local", b".cache", b".ssh", b".var", b".git"];

/// True when the path sits in one of the world-writable scratch directories,
/// or when a *directory* along the way is dot-prefixed and is not one of the
/// conventional ones. The final component is not tested: a collector that
/// looked for `.bashrc` found exactly what it went looking for.
pub fn is_hidden_path(p: &Path) -> bool {
    for dir in ["/tmp", "/dev/shm", "/var/tmp"] {
        if p.starts_with(dir) {
            return true;
        }
    }
    let mut dirs: Vec<&OsStr> = p
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n),
            _ => None,
        })
        .collect();
    dirs.pop();
    dirs.iter().any(|n| {
        let bytes = n.as_bytes();
        bytes.starts_with(b".") && bytes != b"." && !CONVENTIONAL_DOT_DIRS.contains(&bytes)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("unbidden-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn reads_are_capped_and_report_truncation() {
        let dir = tmpdir("cap");
        let mut f = File::create(dir.join("big")).unwrap();
        f.write_all(&vec![b'A'; 5000]).unwrap();
        let root = Root::at(&dir).unwrap();
        let (bytes, truncated) = root.read_capped("big", 100).unwrap();
        assert_eq!(bytes.len(), 100);
        assert!(truncated);
        let (bytes, truncated) = root.read_capped("big", 10_000).unwrap();
        assert_eq!(bytes.len(), 5000);
        assert!(!truncated);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn symlinks_cannot_escape_the_scan_root() {
        let dir = tmpdir("escape");
        std::fs::write(dir.join("inside"), b"image contents").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join("passwd")).unwrap();
        let root = Root::at(&dir).unwrap();

        // The link names an absolute path; inside a scan root it must resolve
        // against the root, not against the analyst's own filesystem.
        match root.read("passwd") {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            Ok(bytes) => panic!("escaped the root and read {} bytes of the host's /etc/passwd", bytes.len()),
        }
        assert_eq!(root.read_link("passwd").unwrap(), PathBuf::from("/etc/passwd"));
        assert_eq!(root.read("inside").unwrap(), b"image contents");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_no_follow_stat_still_cannot_escape_through_its_parents() {
        let dir = tmpdir("statescape");
        std::fs::create_dir_all(dir.join("image/etc")).unwrap();
        std::fs::write(dir.join("image/etc/real"), b"inside").unwrap();
        // An attacker-named path whose PARENT is an absolute symlink. The
        // final component is not followed, but the parents still resolve.
        std::os::unix::fs::symlink("/etc", dir.join("image/escape")).unwrap();

        let root = Root::at(dir.join("image")).unwrap();
        assert!(root.stat("etc/real").is_ok());
        match root.stat("escape/passwd") {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            Ok(_) => panic!("a no-follow stat resolved out of the scan root"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_symlink_out_of_a_home_is_recorded_but_never_read() {
        // A planted link turns the scanner into an exfiltration channel: the
        // account that writes ~/.bashrc need not be able to read /etc/shadow,
        // but this process can, and whatever it reads lands in a report.
        let dir = tmpdir("escaping");
        std::fs::create_dir_all(dir.join("home/alice/dotfiles")).unwrap();
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/shadow"), b"root:$6$SALT$HASH:19000:0:99999:7:::\n").unwrap();
        std::fs::write(dir.join("home/alice/dotfiles/bashrc"), b"export EDITOR=vi\n").unwrap();
        std::os::unix::fs::symlink("/etc/shadow", dir.join("home/alice/.bashrc")).unwrap();
        std::os::unix::fs::symlink("/home/alice/dotfiles/bashrc", dir.join("home/alice/.profile")).unwrap();

        let root = Root::at(&dir).unwrap();

        // Before the homes are known nothing is restricted, which is why the
        // scan declares them before any collector runs.
        assert!(root.escaping_link(Path::new("home/alice/.bashrc")).is_none());

        root.set_homes(vec![PathBuf::from("/home/alice")]);
        assert_eq!(
            root.escaping_link(Path::new("home/alice/.bashrc")),
            Some(PathBuf::from("/etc/shadow"))
        );
        let err = root.read("home/alice/.bashrc").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            err.to_string(),
            "home/alice/.bashrc leads out of its owner's home to /etc/shadow; recorded as a link, not followed"
        );

        // A link inside the same home is how every dotfile manager works and
        // is still followed.
        assert!(root.escaping_link(Path::new("home/alice/.profile")).is_none());
        assert_eq!(root.read("home/alice/.profile").unwrap(), b"export EDITOR=vi\n");

        // And a link outside any home is not this rule's business.
        assert!(root.escaping_link(Path::new("etc/shadow")).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_home_escape_is_caught_however_the_link_is_spelled() {
        // The first version compared the link's text against the home, so a
        // relative `..` target, a second hop, or a linked directory partway
        // down the path all read straight through.
        let dir = tmpdir("chains");
        std::fs::create_dir_all(dir.join("home/alice/dotfiles")).unwrap();
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/shadow"), b"root:$6$SALT$HASH:19000:0:99999:7:::\n").unwrap();
        std::fs::write(dir.join("home/alice/dotfiles/zshrc"), b"export EDITOR=vi\n").unwrap();
        let link = |to: &str, at: &str| std::os::unix::fs::symlink(to, dir.join(at)).unwrap();
        link("../../etc/shadow", "home/alice/.bashrc");
        link("hop", "home/alice/.profile");
        link("/etc/shadow", "home/alice/hop");
        link("/etc", "home/alice/.config");
        link("dotfiles/../dotfiles/zshrc", "home/alice/.zshrc");

        let root = Root::at(&dir).unwrap();
        root.set_homes(vec![PathBuf::from("/home/alice")]);
        for escape in ["home/alice/.bashrc", "home/alice/.profile", "home/alice/.config/shadow"] {
            assert_eq!(root.escaping_link(Path::new(escape)), Some(PathBuf::from("/etc/shadow")), "{escape}");
            assert_eq!(root.read(escape).unwrap_err().kind(), io::ErrorKind::PermissionDenied, "{escape}");
        }
        assert!(root.escaping_link(Path::new("home/alice/.zshrc")).is_none());
        assert_eq!(root.read("home/alice/.zshrc").unwrap(), b"export EDITOR=vi\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_home_path_that_cannot_be_resolved_is_refused_with_the_reason() {
        let dir = tmpdir("unresolvable");
        std::fs::create_dir_all(dir.join("home/alice")).unwrap();
        std::os::unix::fs::symlink(".loop", dir.join("home/alice/.loop")).unwrap();
        let root = Root::at(&dir).unwrap();
        root.set_homes(vec![PathBuf::from("/home/alice")]);

        // A missing dotfile is the common case and must stay NotFound, which
        // collectors treat as absent rather than as a failure.
        assert_eq!(root.read("home/alice/.bashrc").unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(root.read("home/alice/.loop").is_err());
        assert!(root.escaping_link(Path::new("home/alice/.loop")).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_home_that_is_itself_a_link_still_holds_its_own_files() {
        let dir = tmpdir("linkedhome");
        std::fs::create_dir_all(dir.join("srv/carol")).unwrap();
        std::fs::create_dir_all(dir.join("home")).unwrap();
        std::fs::write(dir.join("srv/carol/real"), b"mine\n").unwrap();
        std::os::unix::fs::symlink("../srv/carol", dir.join("home/carol")).unwrap();
        std::os::unix::fs::symlink("real", dir.join("srv/carol/.bashrc")).unwrap();

        let root = Root::at(&dir).unwrap();
        root.set_homes(vec![PathBuf::from("/home/carol")]);
        assert!(root.escaping_link(Path::new("home/carol/.bashrc")).is_none());
        assert_eq!(root.read("home/carol/.bashrc").unwrap(), b"mine\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn without_openat2_an_offline_root_is_confined_by_hand() {
        // RHEL 7 and every kernel before 5.6 lack RESOLVE_IN_ROOT. The root
        // resolves links itself there, and every operation must still land
        // inside the image rather than on the analyst's machine.
        let dir = tmpdir("manual");
        std::fs::create_dir_all(dir.join("image/etc/real")).unwrap();
        std::fs::create_dir_all(dir.join("image/usr/lib")).unwrap();
        std::fs::write(dir.join("image/etc/real/file"), b"inside").unwrap();
        std::fs::write(dir.join("image/usr/lib/unit"), b"vendor").unwrap();
        let link = |to: &str, at: &str| std::os::unix::fs::symlink(to, dir.join("image").join(at)).unwrap();
        link("/etc", "escape");
        link("/etc/passwd", "passwd");
        link("../../../../etc/passwd", "dots");
        link("/usr/lib", "lib");
        link("/escape/nested", "etc/real/chain");
        std::os::unix::fs::symlink("nested", dir.join("image/etc/nested")).unwrap();

        let mut root = Root::at(dir.join("image")).unwrap();
        root.confined = false;

        assert_eq!(root.read("etc/real/file").unwrap(), b"inside");
        assert_eq!(root.read("lib/unit").unwrap(), b"vendor", "an absolute link lands in the image");
        for escape in ["passwd", "dots", "escape/passwd", "escape/real/../../../passwd"] {
            match root.read(escape) {
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound, "{escape}"),
                Ok(b) => panic!("{escape} escaped the root and read {} bytes", b.len()),
            }
        }
        assert!(root.stat("escape/passwd").is_err());
        assert!(root.stat_follow("passwd").is_err());
        assert!(root.read_dir("escape").unwrap().iter().any(|e| e.name == "real"), "listed the image's /etc");
        assert_eq!(root.dir_identity("lib").unwrap(), root.dir_identity("usr/lib").unwrap());
        assert_eq!(root.read_link("escape").unwrap(), PathBuf::from("/etc"));
        // A link loop is refused rather than followed forever.
        assert!(root.read("etc/nested").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reading_a_link_does_not_resolve_its_parents_out_of_the_root() {
        let dir = tmpdir("readlink");
        std::fs::create_dir_all(dir.join("image")).unwrap();
        std::fs::create_dir_all(dir.join("outside")).unwrap();
        std::os::unix::fs::symlink("SECRET-TARGET", dir.join("outside/link")).unwrap();
        std::os::unix::fs::symlink(dir.join("outside"), dir.join("image/escape")).unwrap();

        let root = Root::at(dir.join("image")).unwrap();
        assert!(root.read_link("escape/link").is_err(), "read a link that lives outside the image");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn absent_search_paths_are_not_failures() {
        let dir = tmpdir("absent");
        let root = Root::at(&dir).unwrap();
        assert!(root.read_dir_optional("etc/systemd/system").unwrap().is_empty());
        assert!(root.read_dir("etc/systemd/system").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_directory_reached_by_two_names_has_one_identity() {
        let dir = tmpdir("merged");
        std::fs::create_dir_all(dir.join("usr/lib")).unwrap();
        std::os::unix::fs::symlink("usr/lib", dir.join("lib")).unwrap();
        let root = Root::at(&dir).unwrap();
        assert_eq!(root.dir_identity("lib").unwrap(), root.dir_identity("usr/lib").unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn source_paths_are_reported_as_an_operator_would_type_them() {
        let live = Root::live().unwrap();
        assert_eq!(live.abs("etc/crontab"), PathBuf::from("/etc/crontab"));
        assert_eq!(live.abs("/etc/crontab"), PathBuf::from("/etc/crontab"));
    }

    #[test]
    fn hidden_paths() {
        assert!(is_hidden_path(Path::new("/tmp/x")));
        assert!(is_hidden_path(Path::new("/dev/shm/x")));
        assert!(is_hidden_path(Path::new("/var/tmp/x")));
        assert!(is_hidden_path(Path::new("/home/u/.hoard/payload.sh")));
        assert!(is_hidden_path(Path::new("/usr/lib/.x/mod.so")));

        // Standard locations are not hiding anything, and neither is a
        // dotfile a collector went looking for by name.
        assert!(!is_hidden_path(Path::new("/home/u/.config/autostart/x.desktop")));
        assert!(!is_hidden_path(Path::new("/home/u/.ssh/authorized_keys")));
        assert!(!is_hidden_path(Path::new("/home/u/.bashrc")));
        assert!(!is_hidden_path(Path::new("/srv/repo/.git/hooks/pre-commit")));
        assert!(!is_hidden_path(Path::new("/usr/lib/systemd/system/x.service")));
    }
}

impl Root {
    /// The inverse of `abs`: turn a reported source path back into the
    /// root-relative form every Root operation takes.
    pub fn rel(&self, abs: &Path) -> PathBuf {
        let stripped = abs.strip_prefix(&self.base).unwrap_or(abs);
        strip_leading_slash(stripped).to_path_buf()
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Reads an extended attribute without following a final symlink.
    ///
    /// This is the one filesystem access the Root cannot confine with
    /// `openat2`: Linux grew a `getxattrat` only in 6.13, `fgetxattr` on an
    /// `O_PATH` descriptor is refused, and the alternative — reaching the
    /// file through `/proc/self/fd` — is a magic link, which is exactly what
    /// the resolve flags elsewhere refuse. So the path is named.
    ///
    /// What that costs: on an offline root, a symlinked *parent* directory
    /// could redirect this read outside the image. The caller must therefore
    /// only pass paths it assembled from directories it entered itself
    /// without following a link — which is what the deep walk does. The rule
    /// lives here, in one place, rather than in every caller's head.
    pub fn xattr(&self, rel: impl AsRef<Path>, name: &str, buf: &mut [u8]) -> rustix::io::Result<usize> {
        let abs = self.abs(rel);
        let cap = buf.len();
        rustix::fs::lgetxattr(&abs, name, buf).map(|n| n.min(cap))
    }
}

/// Btrfs gives every subvolume its own device number while they all live on
/// one filesystem, so a device comparison alone reports `/home` as a separate
/// disk on a default Fedora, openSUSE or Arch install.
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;

impl Root {
    /// An identifier for the filesystem a path sits on, stable across the
    /// subvolumes of one btrfs. None where the distinction does not arise,
    /// which keeps the device rule in force for every other filesystem.
    pub fn filesystem_id(&self, rel: impl AsRef<Path>) -> Option<u64> {
        let rel = strip_leading_slash(rel.as_ref());
        let rel = if rel.as_os_str().is_empty() { Path::new(".") } else { rel };
        let fd = self.open_raw(rel, OFlags::PATH | OFlags::DIRECTORY).ok()?;
        if rustix::fs::fstatfs(&fd).ok()?.f_type as i64 != BTRFS_SUPER_MAGIC {
            return None;
        }
        // btrfs builds its filesystem id from the volume UUID and then XORs
        // the subvolume's object id into it — the low 32 bits get the top
        // half of that object id, which is always zero for the small,
        // sequential ids subvolumes actually get, and the high 32 bits get
        // the rest. So the low word identifies the filesystem and the high
        // word identifies the subvolume within it.
        //
        // statfs exposes the two words but rustix keeps them private;
        // statvfs packs the same pair into one u64, low word first.
        Some(rustix::fs::fstatvfs(&fd).ok()?.f_fsid as u64 & 0xffff_ffff)
    }
}
