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
        if !confined && !live {
            return Err(io::Error::other(
                "offline scan roots need openat2 with RESOLVE_IN_ROOT (Linux 5.6+); \
                 without it a symlink in the image can escape to the host filesystem",
            ));
        }
        Ok(Root { fd, base: path.to_path_buf(), live, confined })
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
        } else {
            Ok(rustix::fs::openat(&self.fd, rel, flags, Mode::empty())?)
        }
    }

    pub fn open(&self, rel: impl AsRef<Path>) -> io::Result<File> {
        Ok(File::from(self.open_raw(rel.as_ref(), OFlags::RDONLY)?))
    }

    /// Opens without following a final-component symlink. Use where the
    /// distinction is evidence: an autostart file that is a link to somewhere
    /// else is a fact about the entry, not a detail to resolve through.
    pub fn open_nofollow(&self, rel: impl AsRef<Path>) -> io::Result<File> {
        Ok(File::from(self.open_raw(rel.as_ref(), OFlags::RDONLY | OFlags::NOFOLLOW)?))
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
        let st = if self.confined && at.is_empty() {
            // statat cannot express RESOLVE_IN_ROOT, so resolve through an
            // openat2 handle and stat that instead.
            let fd = self.open_raw(rel, OFlags::PATH)?;
            rustix::fs::statat(&fd, "", AtFlags::EMPTY_PATH)?
        } else {
            rustix::fs::statat(&self.fd, rel, at | AtFlags::SYMLINK_NOFOLLOW.intersection(at))?
        };
        Ok(meta_of(&st))
    }

    pub fn exists(&self, rel: impl AsRef<Path>) -> bool {
        self.stat(rel).is_ok()
    }

    pub fn read_link(&self, rel: impl AsRef<Path>) -> io::Result<PathBuf> {
        let rel = strip_leading_slash(rel.as_ref());
        let target = rustix::fs::readlinkat(&self.fd, rel, Vec::new())?;
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
    let secs = st.st_mtime as i64;
    let mtime = Some(if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
    });
    Meta {
        uid: st.st_uid as u32,
        gid: st.st_gid as u32,
        mode,
        size: st.st_size as u64,
        mtime,
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
const CONVENTIONAL_DOT_DIRS: [&[u8]; 5] = [b".config", b".local", b".cache", b".ssh", b".var"];

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
}
