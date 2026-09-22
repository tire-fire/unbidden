//! The three phases: collect, enrich, render. This module owns the first and
//! the record of how well it went.
//!
//! Collectors are independent, run in parallel, and know nothing of each
//! other. One that fails — or panics on hostile input — is recorded as a
//! failed collector and the scan continues, because a scan that aborts on the
//! one file the attacker crafted is a scan the attacker controls.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::entry::{Entry, Flag, Kind};
use crate::root::{DirEnt, READ_CAP, Root, is_hidden_path};
use crate::users::{self, User};

pub trait Collector: Sync {
    fn name(&self) -> &'static str;

    /// Collectors reading /proc, /sys or a running daemon declare it, so an
    /// offline root knows to skip them rather than report nothing.
    fn requires_live(&self) -> bool {
        false
    }

    /// True for the three collectors that need a whole-filesystem traversal.
    fn deep_only(&self) -> bool {
        false
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry>;
}

pub struct Ctx<'a> {
    pub root: &'a Root,
    pub users: &'a [User],
    pub deep: bool,
    unreadable: Vec<String>,
    truncated: Vec<String>,
}

impl<'a> Ctx<'a> {
    /// A bounded read that records what it could not open. Absent paths are
    /// normal — most search paths do not exist on most hosts — but an
    /// unreadable one is the difference between "nothing there" and "could
    /// not look", and §7 of the spec makes that distinction load-bearing.
    pub fn read(&mut self, rel: impl AsRef<Path>) -> Option<Vec<u8>> {
        self.read_capped(rel, READ_CAP)
    }

    pub fn read_capped(&mut self, rel: impl AsRef<Path>, cap: usize) -> Option<Vec<u8>> {
        let rel = rel.as_ref();

        // Opening a FIFO for reading blocks until someone writes to it, and a
        // collector that hangs cannot be rescued by catching a panic. An
        // attacker plants one by creating a named pipe where a config file is
        // expected. A directory in the same place is the cheaper version of
        // the same trick: it fails with EISDIR, which would otherwise demote
        // the collector to Partial and declare the whole baseline
        // incomparable over one planted symlink.
        match self.root.stat_follow(rel) {
            Ok(meta) if !meta.is_file => {
                self.truncated.push(format!("{}: not a regular file, not read", rel.display()));
                return None;
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(_) => {}
        }

        // A symlink out of its owner's home is refused by the root (§3), and
        // the refusal is the policy working, not a path the scan could not
        // reach. Any user can plant one in their own home, so recording it as
        // unreadable would let every account on the host declare every later
        // baseline incomparable.
        if let Some(target) = self.root.escaping_link(rel) {
            self.note_limited(format!(
                "{}: leads out of its owner's home to {}, not followed",
                rel.display(),
                target.display()
            ));
            return None;
        }

        match self.root.read_capped(rel, cap) {
            Ok((bytes, truncated)) => {
                // A read that hit its cap is not a read that failed. Folding
                // the two together would demote a collector to Partial — and
                // so declare the whole baseline incomparable — because one
                // file was larger than the ceiling, which is the ceiling
                // doing its job.
                if truncated {
                    self.truncated.push(format!("{} (read to {cap} bytes)", rel.display()));
                }
                Some(bytes)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                self.unreadable.push(format!("{}: {e}", rel.display()));
                None
            }
        }
    }

    pub fn dir(&mut self, rel: impl AsRef<Path>) -> Vec<DirEnt> {
        let rel = rel.as_ref();
        match self.root.read_dir(rel) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                self.unreadable.push(format!("{}: {e}", rel.display()));
                Vec::new()
            }
        }
    }

    pub fn note_unreadable(&mut self, what: impl std::fmt::Display) {
        self.unreadable.push(what.to_string());
    }

    /// A read the scan limited on purpose, or content it read but declined to
    /// interpret: a file past its cap, a link it refused to follow, a database
    /// too malformed to parse. These are properties of what is on disk, the
    /// same on every run, so unlike `note_unreadable` they do not make the
    /// collector Partial. Content an unprivileged user controls must never be
    /// able to declare a baseline incomparable.
    pub fn note_limited(&mut self, what: impl std::fmt::Display) {
        self.truncated.push(what.to_string());
    }

    /// Builds an Entry with the facts about its backing file already filled
    /// in. Every collector routes through here so that ownership, permissions
    /// and the file-shaped flags are derived one way, once.
    pub fn entry(&mut self, kind: Kind, rel: impl AsRef<Path>, name: impl Into<String>) -> Entry {
        let rel = rel.as_ref();
        let abs = self.root.abs(rel);
        let mut e = Entry::new(kind, &abs, name);
        // Reported path for the operator, root-relative path for identity.
        e.rekey(rel);

        if let Ok(link) = self.root.stat(rel) {
            // The link's own timestamp is the interesting one: for an
            // /etc/rc2.d/S01foo symlink it records when the entry was
            // enabled, not when the script behind it was written.
            e.mtime = link.mtime;

            let meta = if link.is_symlink {
                if let Ok(t) = self.root.read_link(rel) {
                    e.note("symlink_target", t.to_string_lossy());
                }
                match self.root.stat_follow(rel) {
                    Ok(target) => target,
                    Err(_) => {
                        e.note("dangling_symlink", "true");
                        link
                    }
                }
            } else {
                link
            };

            e.owner_uid = meta.uid;
            e.mode = meta.perms();
            // Permissions come from what the path resolves to. A symlink's
            // own bits are always 0777 and the kernel ignores them, so
            // reading them would flag every SysV rc symlink on every host.
            //
            // The test applies only to ordinary files and directories. A unit
            // masked the documented way is a symlink to /dev/null, and a
            // character device is world-writable by design — reading its mode
            // as the entry's would flag every masked unit on every host.
            if (meta.is_file || meta.is_dir) && meta.world_writable() {
                e.flag(Flag::WorldWritable);
            }
            if let Some(owner) = self.home_owner(&abs) {
                // §5: accounts come from three places and the difference
                // matters. A home directory with no passwd entry is not the
                // same fact as an ordinary account, and an operator reading
                // a per-user entry should not have to go and work out which
                // this was.
                e.note("user", owner.name.clone());
                e.note("user_discovered_via", owner.source);
                if owner.uid.is_some_and(|uid| uid != meta.uid) {
                    e.flag(Flag::OwnerMismatch);
                }
            }
        }

        // A world-writable directory is as good as a world-writable file:
        // anyone can replace what is inside it.
        if let Some(parent) = rel.parent() {
            if let Ok(meta) = self.root.stat(parent) {
                if meta.world_writable() && !is_sticky(meta.mode) {
                    e.flag(Flag::WorldWritable);
                }
            }
        }

        // Judged inside the scan root, not on the reported path: an image
        // mounted under /tmp must not report every file in it as hidden.
        if is_hidden_path(&Path::new("/").join(rel)) {
            e.flag(Flag::HiddenPath);
        }
        e
    }

    /// The user whose home contains this path, if any.
    ///
    /// Both sides are compared inside the scan root. Homes are recorded as
    /// they sit in the image (`/home/alice`) while the reported path carries
    /// the root prefix, so comparing them directly matched nothing at all on
    /// an offline root — and OwnerMismatch was quietly dead there.
    fn home_owner(&self, abs: &Path) -> Option<&User> {
        let here = self.root.rel(abs);
        self.users
            .iter()
            .filter(|u| u.has_real_home() && here.starts_with(self.root.rel(&u.home)))
            .max_by_key(|u| u.home.as_os_str().len())
    }
}

fn is_sticky(mode: u32) -> bool {
    mode & 0o1000 != 0
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Status {
    Complete,
    /// Ran, but could not read everything it needed. A baseline taken this
    /// way is not comparable with one that was complete.
    Partial { unreadable: Vec<String> },
    Skipped { reason: String },
    Failed { error: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorStatus {
    pub name: String,
    #[serde(flatten)]
    pub status: Status,
    pub entries: usize,
    /// Reads that deliberately returned less than the whole file: one that
    /// hit its cap, a path that was not a regular file, a symlink out of a
    /// home that was not followed, content too malformed to interpret.
    /// Deterministic, so it does not make two baselines incomparable, but the
    /// operator should still see it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub truncated: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub unbidden_version: String,
    pub schema_version: u32,
    pub scan_time: i64,
    pub hostname: String,
    pub kernel: String,
    pub distro_id: String,
    pub distro_version: String,
    pub root: PathBuf,
    pub live: bool,
    pub deep: bool,
    pub privileged: bool,
    /// Whether enablement was read from systemd or inferred from symlinks.
    /// A baseline taken one way is not comparable with one taken the other:
    /// every unit's enablement would appear to have changed.
    #[serde(default = "inferred")]
    pub enablement: String,
    pub collectors: Vec<CollectorStatus>,
    /// Enrichment stages that panicked, and what each one left undone. The
    /// entries are still reported, but the facts that stage adds — a
    /// provenance verdict, a flag — may be missing from them, so a scan
    /// carrying any of these is not comparable with one that carries none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enrichment_failures: Vec<String>,
}

pub fn inferred() -> String {
    "inferred".to_string()
}

/// The JSON contract of §10. Bump only for additive change; a reader must
/// tolerate fields it does not know.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scan {
    pub header: Header,
    pub entries: Vec<Entry>,
}

pub struct Options {
    pub deep: bool,
}

pub fn run(root: &Root, opts: &Options, collectors: &[Box<dyn Collector>]) -> Scan {
    let users = users::discover(root);
    // Every read from here on is subject to the escaping-symlink rule.
    root.set_homes(users.iter().filter(|u| u.has_real_home()).map(|u| u.home.clone()).collect());
    let mut results: Vec<(CollectorStatus, Vec<Entry>)> = Vec::new();

    std::thread::scope(|scope| {
        let handles: Vec<_> = collectors
            .iter()
            .map(|c| {
                let users = &users;
                scope.spawn(move || {
                    let mut cx = Ctx {
                        root,
                        users,
                        deep: opts.deep,
                        unreadable: Vec::new(),
                        truncated: Vec::new(),
                    };
                    if c.deep_only() && !opts.deep {
                        return (skipped(c.name(), "needs --deep"), Vec::new());
                    }
                    if c.requires_live() && !root.is_live() {
                        return (skipped(c.name(), "needs a live host"), Vec::new());
                    }
                    let collected = catch_unwind(AssertUnwindSafe(|| c.collect(&mut cx)));
                    let unreadable = cx.unreadable;
                    let truncated = cx.truncated;
                    match collected {
                        Ok(entries) => {
                            let status = if unreadable.is_empty() {
                                Status::Complete
                            } else {
                                Status::Partial { unreadable }
                            };
                            let st = CollectorStatus {
                                name: c.name().to_string(),
                                entries: entries.len(),
                                status,
                                truncated,
                            };
                            (st, entries)
                        }
                        Err(payload) => (
                            CollectorStatus {
                                name: c.name().to_string(),
                                entries: 0,
                                status: Status::Failed { error: panic_message(payload) },
                                truncated,
                            },
                            Vec::new(),
                        ),
                    }
                })
            })
            .collect();

        for h in handles {
            match h.join() {
                Ok(r) => results.push(r),
                // catch_unwind already covers collector bodies; this is the
                // belt to that suspenders.
                Err(payload) => results.push((
                    CollectorStatus {
                        name: "unknown".into(),
                        entries: 0,
                        status: Status::Failed { error: panic_message(payload) },
                        truncated: Vec::new(),
                    },
                    Vec::new(),
                )),
            }
        }
    });

    results.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    let mut entries = Vec::new();
    let mut statuses = Vec::new();
    for (status, mut es) in results {
        statuses.push(status);
        entries.append(&mut es);
    }
    entries.sort_by(|a, b| (a.kind, &a.source, &a.name).cmp(&(b.kind, &b.source, &b.name)));

    Scan { header: header(root, opts, statuses), entries }
}

fn skipped(name: &str, reason: &str) -> CollectorStatus {
    CollectorStatus {
        name: name.to_string(),
        entries: 0,
        status: Status::Skipped { reason: reason.to_string() },
        truncated: Vec::new(),
    }
}

pub fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "collector panicked".to_string()
    }
}

fn header(root: &Root, opts: &Options, collectors: Vec<CollectorStatus>) -> Header {
    let uname = rustix::system::uname();
    let (distro_id, distro_version) = os_release(root);
    Header {
        unbidden_version: env!("CARGO_PKG_VERSION").to_string(),
        schema_version: SCHEMA_VERSION,
        scan_time: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        // Live-only facts: on an offline root these describe the analyst's
        // machine, so they come from the image where the image can answer.
        hostname: root
            .read_capped("etc/hostname", 4096)
            .ok()
            .map(|(b, _)| String::from_utf8_lossy(&b).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| uname.nodename().to_string_lossy().into_owned()),
        kernel: if root.is_live() {
            uname.release().to_string_lossy().into_owned()
        } else {
            String::new()
        },
        distro_id,
        distro_version,
        root: root.abs(""),
        live: root.is_live(),
        deep: opts.deep,
        privileged: rustix::process::geteuid().is_root(),
        enablement: inferred(),
        collectors,
        enrichment_failures: Vec::new(),
    }
}

/// Distro detection reads the scan root, never the running system (§11).
fn os_release(root: &Root) -> (String, String) {
    let mut id = String::new();
    let mut version = String::new();
    for path in ["etc/os-release", "usr/lib/os-release"] {
        let Ok((bytes, _)) = root.read_capped(path, 64 * 1024) else { continue };
        for line in String::from_utf8_lossy(&bytes).lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            let v = v.trim_matches('"').to_string();
            match k {
                "ID" if id.is_empty() => id = v,
                "VERSION_ID" if version.is_empty() => version = v,
                _ => {}
            }
        }
        if !id.is_empty() {
            break;
        }
    }
    (id, version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Trigger;

    struct Panicky;
    impl Collector for Panicky {
        fn name(&self) -> &'static str {
            "panicky"
        }
        fn collect(&self, _: &mut Ctx) -> Vec<Entry> {
            panic!("hostile input, line 3");
        }
    }

    struct Fine;
    impl Collector for Fine {
        fn name(&self) -> &'static str {
            "fine"
        }
        fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
            let mut e = cx.entry(Kind::RcLocal, "etc/rc.local", "rc.local");
            e.trigger = Trigger::Boot;
            vec![e]
        }
    }

    #[test]
    fn a_panicking_collector_does_not_take_the_scan_with_it() {
        let dir = std::env::temp_dir().join(format!("unbidden-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/rc.local"), "#!/bin/sh\n/tmp/x\n").unwrap();
        std::fs::write(dir.join("etc/os-release"), "ID=debian\nVERSION_ID=\"12\"\n").unwrap();

        let root = Root::at(&dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Panicky), Box::new(Fine)];
        let scan = run(&root, &Options { deep: false }, &collectors);

        assert_eq!(scan.entries.len(), 1, "the healthy collector still reported");
        assert_eq!(scan.header.distro_id, "debian");
        let failed = scan.header.collectors.iter().find(|c| c.name == "panicky").unwrap();
        match &failed.status {
            Status::Failed { error } => assert!(error.contains("hostile input")),
            other => panic!("expected a recorded failure, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_entry_under_a_home_says_how_that_account_was_found() {
        let dir = std::env::temp_dir().join(format!("unbidden-usersrc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::create_dir_all(dir.join("home/ghost/.config/autostart")).unwrap();
        std::fs::write(dir.join("etc/passwd"), "alice:x:1000:1000::/home/alice:/bin/sh\n").unwrap();
        std::fs::create_dir_all(dir.join("home/alice")).unwrap();
        std::fs::write(dir.join("home/alice/.bashrc"), b"export X=1\n").unwrap();
        std::fs::write(dir.join("home/ghost/.config/autostart/x.desktop"), b"[Desktop Entry]\n").unwrap();

        let root = Root::at(&dir).unwrap();
        let users = crate::users::discover(&root);
        let mut cx = Ctx {
            root: &root,
            users: &users,
            deep: false,
            unreadable: Vec::new(),
            truncated: Vec::new(),
        };

        let known = cx.entry(Kind::ShellProfile, "home/alice/.bashrc", ".bashrc");
        assert_eq!(known.raw["user"], "alice");
        assert_eq!(known.raw["user_discovered_via"], "passwd");

        // A home with no account behind it is exactly the case an operator
        // wants flagged as odd, and it is invisible if the source is dropped.
        let ghost = cx.entry(Kind::XdgAutostart, "home/ghost/.config/autostart/x.desktop", "x.desktop");
        assert_eq!(ghost.raw["user"], "ghost");
        assert_eq!(ghost.raw["user_discovered_via"], "home-dir");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_fifo_planted_where_a_config_belongs_does_not_hang_the_scan() {
        // Opening a FIFO for reading blocks until a writer appears. A
        // collector that hangs cannot be rescued by catching a panic, so this
        // test would not fail — it would never finish.
        let dir = std::env::temp_dir().join(format!("unbidden-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc/cron.d")).unwrap();
        std::fs::create_dir_all(dir.join("etc/cron.daily")).unwrap();

        let fd = rustix::fs::open(dir.join("etc/cron.d"), rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY, rustix::fs::Mode::empty()).unwrap();
        rustix::fs::mknodat(&fd, "trap", rustix::fs::FileType::Fifo, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR, 0).unwrap();

        let root = Root::at(&dir).unwrap();
        let users: Vec<User> = Vec::new();
        let mut cx = Ctx {
            root: &root,
            users: &users,
            deep: false,
            unreadable: Vec::new(),
            truncated: Vec::new(),
        };

        assert!(cx.read("etc/cron.d/trap").is_none());
        assert!(cx.truncated.iter().any(|t| t.contains("not a regular file")));
        assert!(cx.unreadable.is_empty(), "a planted FIFO must not declare the baseline incomparable");

        // A directory in the same position is the cheaper version of the
        // same trick.
        assert!(cx.read("etc/cron.daily").is_none());
        assert!(cx.unreadable.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn world_writable_parent_flags_the_entry() {
        let dir = std::env::temp_dir().join(format!("unbidden-ww-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc/cron.d")).unwrap();
        std::fs::write(dir.join("etc/cron.d/job"), "* * * * * root /tmp/x\n").unwrap();
        std::fs::set_permissions(dir.join("etc/cron.d"), std::os::unix::fs::PermissionsExt::from_mode(0o777)).unwrap();

        let root = Root::at(&dir).unwrap();
        let users: Vec<User> = Vec::new();
        let mut cx = Ctx {
            root: &root,
            users: &users,
            deep: false,
            unreadable: Vec::new(),
            truncated: Vec::new(),
        };
        let e = cx.entry(Kind::Cron, "etc/cron.d/job", "job");
        assert!(e.has_flag(Flag::WorldWritable));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_symlinked_entry_is_not_world_writable_just_for_being_a_symlink() {
        // A symlink's own mode is always 0777 and the kernel ignores it.
        // Reading it would flag every /etc/rc2.d/S01foo on every host.
        let dir = std::env::temp_dir().join(format!("unbidden-symperm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc/init.d")).unwrap();
        std::fs::create_dir_all(dir.join("etc/rc2.d")).unwrap();
        std::fs::write(dir.join("etc/init.d/ssh"), "#!/bin/sh
").unwrap();
        std::fs::set_permissions(
            dir.join("etc/init.d/ssh"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink("../init.d/ssh", dir.join("etc/rc2.d/S01ssh")).unwrap();
        std::os::unix::fs::symlink("../init.d/gone", dir.join("etc/rc2.d/S02gone")).unwrap();

        let root = Root::at(&dir).unwrap();
        let users: Vec<User> = Vec::new();
        let mut cx = Ctx {
            root: &root,
            users: &users,
            deep: false,
            unreadable: Vec::new(),
            truncated: Vec::new(),
        };

        let e = cx.entry(Kind::SysvInit, "etc/rc2.d/S01ssh", "S01ssh");
        assert!(!e.has_flag(Flag::WorldWritable), "took permissions from the link, not its target");
        assert_eq!(e.mode, 0o755);
        assert_eq!(e.raw["symlink_target"], "../init.d/ssh");

        let e = cx.entry(Kind::SysvInit, "etc/rc2.d/S02gone", "S02gone");
        assert!(!e.has_flag(Flag::WorldWritable), "a dangling link is not world-writable either");
        assert_eq!(e.raw["dangling_symlink"], "true");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
