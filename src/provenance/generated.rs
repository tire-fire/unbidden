//! Files that are neither packaged nor attacker-authored: something on the
//! system produced them at runtime.
//!
//! Without this, every snap on an Ubuntu or Mint host reports Unpackaged —
//! the same verdict an attacker's unit gets, and the flag the tool leads
//! with. That is the largest false-positive source in the supported set.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::entry::Provenance;
use crate::root::Root;

use super::Answers;

pub fn classify(_root: &Root, wanted: &BTreeSet<PathBuf>) -> Answers {
    let mut out = Answers::new();
    for path in wanted {
        if let Some(by) = producer(path) {
            out.insert(path.clone(), Provenance::GeneratedBy { by: by.to_string() });
        }
    }
    out
}

fn producer(rel: &Path) -> Option<&'static str> {
    let text = rel.to_string_lossy();
    let name = rel.file_name()?.to_string_lossy().into_owned();

    // snapd writes its units into the normal unit directories, and dpkg owns
    // none of them.
    if text.starts_with("snap/") || text.starts_with("var/lib/snapd/") {
        return Some("snapd");
    }
    if name.starts_with("snap.") || name.starts_with("snap-") {
        return Some("snapd");
    }

    // Anything a systemd generator produced lives under a generator
    // directory. The generator itself is a separate entry and a separate
    // mechanism; this is only about its output.
    if text.starts_with("run/systemd/generator")
        || text.starts_with("run/systemd/transient")
        || text.starts_with("run/systemd/system.control")
    {
        return Some("systemd-generator");
    }

    if text.starts_with("run/cloud-init/") || name.starts_with("cloud-init") || name.starts_with("cloud-final") {
        return Some("cloud-init");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snap_units_are_not_reported_as_unpackaged() {
        assert_eq!(producer(Path::new("etc/systemd/system/snap.firefox.firefox.service")), Some("snapd"));
        assert_eq!(producer(Path::new("snap/core22/1122/etc/rc.local")), Some("snapd"));
        assert_eq!(producer(Path::new("run/systemd/generator/foo.service")), Some("systemd-generator"));
        assert_eq!(producer(Path::new("etc/systemd/system/evil.service")), None);
        assert_eq!(producer(Path::new("usr/lib/systemd/system/ssh.service")), None);
    }
}
