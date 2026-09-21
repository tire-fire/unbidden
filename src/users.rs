//! Account discovery without NSS.
//!
//! A static binary has no libc name service, so accounts come from parsing
//! /etc/passwd. That misses LDAP and SSSD users, so the set is widened with
//! every home directory and crontab spool actually present on disk, and each
//! user records how it was found. The gap is documented, never papered over.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::root::{READ_CAP, Root};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: Option<u32>,
    pub home: PathBuf,
    pub shell: Option<String>,
    /// passwd, home-dir, or cron-spool — how this account came to light.
    pub source: &'static str,
}

impl User {
    /// A path under this user's home, as a root-relative path.
    pub fn in_home(&self, rel: &str) -> PathBuf {
        self.home.join(rel)
    }

    /// Whether this account's home is somewhere a person keeps files.
    ///
    /// System accounts are routinely given a home of `/`, `/proc` or
    /// `/nonexistent`. Treating those as homes makes every file beneath them
    /// look like it belongs to that account — on this machine the `rtkit`
    /// account homed at `/proc` flagged all 248 loaded kernel modules as
    /// owner-mismatched.
    pub fn has_real_home(&self) -> bool {
        const SYSTEM_TREES: [&str; 13] = [
            "/proc", "/sys", "/dev", "/run", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc",
            "/var", "/srv", "/tmp",
        ];
        if self.home == Path::new("/root") {
            return true;
        }
        if self.home.components().count() < 3 {
            return false;
        }
        !SYSTEM_TREES.iter().any(|t| self.home.starts_with(t))
    }
}

pub fn discover(root: &Root) -> Vec<User> {
    let mut found: BTreeMap<String, User> = BTreeMap::new();

    for line in read_lines(root, "etc/passwd") {
        // name:passwd:uid:gid:gecos:home:shell
        let f: Vec<&[u8]> = line.split(|b| *b == b':').collect();
        if f.len() < 7 {
            continue;
        }
        let name = String::from_utf8_lossy(f[0]).into_owned();
        if name.is_empty() {
            continue;
        }
        let home = PathBuf::from(String::from_utf8_lossy(f[5]).into_owned());
        if home.as_os_str().is_empty() {
            continue;
        }
        found.insert(name.clone(), User {
            name,
            uid: std::str::from_utf8(f[2]).ok().and_then(|s| s.parse().ok()),
            home,
            shell: Some(String::from_utf8_lossy(f[6]).into_owned()),
            source: "passwd",
        });
    }

    let add_home = |home: PathBuf, source: &'static str, found: &mut BTreeMap<String, User>| {
        let name = match home.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => return,
        };
        if found.values().any(|u| u.home == home) {
            return;
        }
        found.entry(name.clone()).or_insert(User {
            name,
            uid: root.stat(&home).ok().map(|m| m.uid),
            home,
            shell: None,
            source,
        });
    };

    for ent in root.read_dir_optional("home").unwrap_or_default() {
        if ent.is_dir {
            add_home(PathBuf::from("/home").join(&ent.name), "home-dir", &mut found);
        }
    }
    if root.exists("root") {
        add_home(PathBuf::from("/root"), "home-dir", &mut found);
    }

    // A crontab spool entry names an account even when passwd does not.
    for spool in ["var/spool/cron", "var/spool/cron/crontabs"] {
        for ent in root.read_dir_optional(spool).unwrap_or_default() {
            let name = ent.name.to_string_lossy().into_owned();
            if ent.is_dir || name.is_empty() || found.contains_key(&name) {
                continue;
            }
            found.insert(name.clone(), User {
                home: PathBuf::from("/home").join(&name),
                name,
                uid: None,
                shell: None,
                source: "cron-spool",
            });
        }
    }

    found.into_values().collect()
}

fn read_lines(root: &Root, rel: &str) -> Vec<Vec<u8>> {
    match root.read_capped(rel, READ_CAP) {
        Ok((bytes, _)) => bytes.split(|b| *b == b'\n').map(|l| l.to_vec()).collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_system_account_homed_at_a_system_tree_is_not_a_home() {
        let user = |home: &str| User {
            name: "x".into(),
            uid: Some(1),
            home: PathBuf::from(home),
            shell: None,
            source: "passwd",
        };
        assert!(user("/home/alice").has_real_home());
        assert!(user("/root").has_real_home());
        assert!(user("/export/home/bob").has_real_home());
        assert!(!user("/").has_real_home(), "bin, daemon, nobody and friends");
        assert!(!user("/proc").has_real_home(), "rtkit");
        assert!(!user("/var/lib/mysql").has_real_home());
        assert!(!user("/srv/http").has_real_home());
    }

    #[test]
    fn passwd_home_and_spool_are_unioned_with_their_sources() {
        let dir = std::env::temp_dir().join(format!("unbidden-users-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::create_dir_all(dir.join("home/ldapuser")).unwrap();
        std::fs::create_dir_all(dir.join("root")).unwrap();
        std::fs::create_dir_all(dir.join("var/spool/cron/crontabs")).unwrap();
        std::fs::write(dir.join("etc/passwd"), "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\nbroken-line\n").unwrap();
        std::fs::write(dir.join("var/spool/cron/crontabs/svcacct"), "* * * * * /tmp/x\n").unwrap();

        let root = Root::at(&dir).unwrap();
        let users = discover(&root);
        let by: BTreeMap<_, _> = users.iter().map(|u| (u.name.as_str(), u)).collect();

        assert_eq!(by["alice"].source, "passwd");
        assert_eq!(by["alice"].uid, Some(1000));
        assert_eq!(by["ldapuser"].source, "home-dir", "a home with no passwd entry still gets scanned");
        assert_eq!(by["svcacct"].source, "cron-spool", "a spool with no passwd entry still gets scanned");
        assert_eq!(by["root"].home, PathBuf::from("/root"));
        assert!(!by.contains_key("broken-line"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
