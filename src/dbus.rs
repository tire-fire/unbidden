//! Authoritative enablement, from systemd itself.
//!
//! A unit file sitting in /etc/systemd/system may do nothing, and a unit
//! enabled through a .wants/ symlink does not look enabled in a directory
//! walk. Conflating presence with enablement is the most common defect in
//! tools of this kind, so where systemd is running it is asked directly.
//!
//! The filesystem walk stays the primary enumeration and this is enrichment,
//! never the reverse: a unit file on disk that systemd has not loaded still
//! has to be reported, and that is exactly where an attacker's unit sits
//! before its first boot.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::entry::{Enablement, Entry, Flag, Kind, Provenance};
use crate::root::Root;

pub struct UnitFile {
    pub state: String,
}

pub struct Manager {
    /// Keyed by the unit file's path on disk, which is what ListUnitFiles
    /// returns and what the collectors recorded as `source`.
    by_path: BTreeMap<PathBuf, UnitFile>,
    /// Keyed by unit name: runtime state for units systemd has loaded.
    active: BTreeMap<String, (String, String)>,
}

impl Manager {
    /// Asks the system manager, with a deadline. Returns None where there is
    /// nothing to ask — an offline root, a container without systemd, a
    /// socket we may not open, or a bus that does not answer — all of which
    /// leave the inferred answer and its DegradedEnablement flag in place.
    ///
    /// The deadline is not a nicety. Enrichment runs after every collector
    /// has finished, so a bus that accepts a connection and then never
    /// replies would hang a completed scan just before it printed anything.
    pub fn query(root: &Root) -> Option<Manager> {
        if !root.is_live() {
            return None;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(query_blocking());
        });
        // The thread is left to its fate if it overruns: this is a one-shot
        // scan, and a stuck D-Bus connection must not outlive its usefulness.
        rx.recv_timeout(QUERY_DEADLINE).ok().flatten()
    }
}

/// Long enough for a loaded machine with thousands of units, short enough
/// that an operator does not think the tool has died.
const QUERY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

impl Manager {
    fn query_inner() -> Option<Manager> {
        let conn = connect()?;

        let mut by_path = BTreeMap::new();
        if let Ok(reply) = call(&conn, "ListUnitFiles") {
            if let Ok(files) = reply.body().deserialize::<Vec<(String, String)>>() {
                for (path, state) in files {
                    by_path.insert(PathBuf::from(path), UnitFile { state });
                }
            }
        }
        if by_path.is_empty() {
            return None;
        }

        let mut active = BTreeMap::new();
        if let Ok(reply) = call(&conn, "ListUnits") {
            type Unit = (String, String, String, String, String, String, zbus::zvariant::OwnedObjectPath, u32, String, zbus::zvariant::OwnedObjectPath);
            if let Ok(units) = reply.body().deserialize::<Vec<Unit>>() {
                for u in units {
                    active.insert(u.0, (u.3, u.4));
                }
            }
        }

        Some(Manager { by_path, active })
    }

    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }
}

fn query_blocking() -> Option<Manager> {
    Manager::query_inner()
}

/// The system bus, and only the system bus.
///
/// systemd's private socket at /run/systemd/private would be the better
/// answer — it needs no broker and is subject to no policy — but zbus cannot
/// speak to it: systemd's replies there carry no valid unique name, and
/// zbus panics reconstructing the message fields. That panic happens on its
/// own executor thread, where catching it is not possible, and the blocking
/// call it was serving then waits forever. A scanner that hangs on a
/// compromised host is worse than one that answers "inferred".
fn connect() -> Option<zbus::blocking::Connection> {
    zbus::blocking::Connection::system().ok()
}

fn call(conn: &zbus::blocking::Connection, method: &str) -> zbus::Result<zbus::Message> {
    conn.call_method(
        Some("org.freedesktop.systemd1"),
        "/org/freedesktop/systemd1",
        Some("org.freedesktop.systemd1.Manager"),
        method,
        &(),
    )
}

/// systemd's own vocabulary is wider than the Entry record's, so the exact
/// string is always recorded alongside the mapped value.
fn enablement_of(state: &str) -> Enablement {
    match state {
        "enabled" | "enabled-runtime" => Enablement::Enabled,
        "disabled" => Enablement::Disabled,
        "masked" | "masked-runtime" => Enablement::Masked,
        "static" | "indirect" | "generated" | "transient" | "alias" | "linked" | "linked-runtime" => {
            Enablement::Static
        }
        _ => Enablement::Unknown,
    }
}

/// Replaces inferred enablement with the authoritative answer, for the units
/// systemd knows about. Everything else keeps its inferred value and its
/// DegradedEnablement flag, which is the honest outcome.
pub fn apply(manager: &Manager, entries: &mut [Entry]) -> usize {
    let mut answered = 0;
    for e in entries {
        if !matches!(e.kind, Kind::SystemdUnit | Kind::SystemdTimer) {
            continue;
        }
        let Some(file) = manager.by_path.get(&e.source) else { continue };

        // Keeping the inferred answer is what makes the symlink-resolution
        // path testable. It is the offline implementation, and a live host
        // is the only place its answers can be checked against systemd's.
        if e.enabled != Enablement::Unknown {
            e.note("inferred_enablement", e.enabled.as_str());
        }
        e.enabled = enablement_of(&file.state);
        e.note("unit_file_state", &file.state);
        e.flags.retain(|f| *f != Flag::DegradedEnablement);
        answered += 1;

        if let Some((active, sub)) = manager.active.get(&e.name) {
            e.note("active_state", active);
            e.note("sub_state", sub);
        }

        // A generated unit was written by a systemd generator, which is
        // itself a persistence mechanism and a separate entry. Saying so
        // here is what lets an operator connect the two.
        if file.state == "generated" {
            e.note("generated", "true");
            if matches!(e.provenance, Provenance::Unpackaged | Provenance::Unknown) {
                e.provenance = Provenance::GeneratedBy { by: "systemd-generator".into() };
                e.flags.retain(|f| *f != Flag::Unpackaged);
            }
        }
    }
    answered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_states_map_onto_the_record_vocabulary() {
        assert_eq!(enablement_of("enabled"), Enablement::Enabled);
        assert_eq!(enablement_of("enabled-runtime"), Enablement::Enabled);
        assert_eq!(enablement_of("disabled"), Enablement::Disabled);
        assert_eq!(enablement_of("masked"), Enablement::Masked);
        assert_eq!(enablement_of("static"), Enablement::Static);
        assert_eq!(enablement_of("generated"), Enablement::Static);
        assert_eq!(enablement_of("bad"), Enablement::Unknown);
        assert_eq!(enablement_of("something-new-in-systemd-260"), Enablement::Unknown);
    }

    #[test]
    fn an_authoritative_answer_replaces_the_inferred_one_and_its_caveat() {
        let mut e = Entry::new(Kind::SystemdUnit, "/etc/systemd/system/evil.service", "evil.service");
        e.enabled = Enablement::Disabled;
        e.flag(Flag::DegradedEnablement);
        e.flag(Flag::Unpackaged);

        let manager = Manager {
            by_path: [(PathBuf::from("/etc/systemd/system/evil.service"), UnitFile { state: "enabled".into() })]
                .into_iter()
                .collect(),
            active: [("evil.service".to_string(), ("active".to_string(), "running".to_string()))]
                .into_iter()
                .collect(),
        };

        let mut entries = vec![e];
        assert_eq!(apply(&manager, &mut entries), 1);
        let e = &entries[0];
        assert_eq!(e.enabled, Enablement::Enabled);
        assert!(!e.has_flag(Flag::DegradedEnablement));
        assert!(e.has_flag(Flag::Unpackaged), "the other findings are untouched");
        assert_eq!(e.raw["active_state"], "active");
        assert_eq!(e.raw["sub_state"], "running");
    }

    #[test]
    fn the_inferred_answer_is_kept_so_the_offline_path_can_be_checked() {
        let mut e = Entry::new(Kind::SystemdUnit, "/usr/lib/systemd/system/a.service", "a.service");
        e.enabled = Enablement::Disabled;
        e.flag(Flag::DegradedEnablement);

        let manager = Manager {
            by_path: [(PathBuf::from("/usr/lib/systemd/system/a.service"), UnitFile { state: "static".into() })]
                .into_iter()
                .collect(),
            active: BTreeMap::new(),
        };
        let mut entries = vec![e];
        apply(&manager, &mut entries);
        assert_eq!(entries[0].enabled, Enablement::Static);
        assert_eq!(entries[0].raw["inferred_enablement"], "disabled");
    }

    #[test]
    fn a_unit_systemd_has_never_heard_of_keeps_the_inferred_answer() {
        // The case that matters: a unit file dropped on disk before its
        // first boot. The filesystem walk found it; systemd has not.
        let mut e = Entry::new(Kind::SystemdUnit, "/etc/systemd/system/planted.service", "planted.service");
        e.enabled = Enablement::Disabled;
        e.flag(Flag::DegradedEnablement);

        let manager = Manager {
            by_path: [(PathBuf::from("/etc/systemd/system/other.service"), UnitFile { state: "enabled".into() })]
                .into_iter()
                .collect(),
            active: BTreeMap::new(),
        };

        let mut entries = vec![e];
        assert_eq!(apply(&manager, &mut entries), 0);
        assert!(entries[0].has_flag(Flag::DegradedEnablement));
        assert_eq!(entries[0].enabled, Enablement::Disabled);
    }

    #[test]
    fn a_generated_unit_is_attributed_to_its_generator_not_called_unpackaged() {
        let mut e = Entry::new(Kind::SystemdUnit, "/run/systemd/generator/x.mount", "x.mount");
        e.provenance = Provenance::Unpackaged;
        e.flag(Flag::Unpackaged);

        let manager = Manager {
            by_path: [(PathBuf::from("/run/systemd/generator/x.mount"), UnitFile { state: "generated".into() })]
                .into_iter()
                .collect(),
            active: BTreeMap::new(),
        };

        let mut entries = vec![e];
        apply(&manager, &mut entries);
        assert!(!entries[0].has_flag(Flag::Unpackaged));
        assert_eq!(entries[0].raw["generated"], "true");
        assert!(matches!(&entries[0].provenance, Provenance::GeneratedBy { by } if by == "systemd-generator"));
    }
}
