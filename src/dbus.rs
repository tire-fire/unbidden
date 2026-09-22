//! Authoritative enablement, from systemd itself.
//!
//! A unit file sitting in /etc/systemd/system may do nothing, and a unit
//! enabled through a .wants/ symlink does not look enabled in a directory
//! walk. Conflating presence with enablement is the most common defect in
//! tools of this kind, so where systemd is running it is asked directly.
//!
//! There is more than one systemd running. Every logged-in user has a manager
//! of their own with its own unit search path, and it is the only thing that
//! can say whether that user's units are enabled. A user without a session has
//! no manager and still has unit files on disk, so absence of a manager is
//! never read as absence of units.
//!
//! The filesystem walk stays the primary enumeration and this is enrichment,
//! never the reverse: a unit file on disk that systemd has not loaded still
//! has to be reported, and that is exactly where an attacker's unit sits
//! before its first boot.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::entry::{Enablement, Entry, Flag, Kind, Provenance};
use crate::root::Root;

/// How the system manager names itself in an answer. User managers are
/// `user:<uid>`, the uid being what /run/user/<uid> gives us without NSS.
const SYSTEM: &str = "system";

/// What every manager said about one unit-file path, keyed by the manager.
///
/// A file under /usr/lib/systemd/user is on the search path of every user
/// manager on the host, so one path can come back with fifty answers, and
/// nothing obliges them to agree.
#[derive(Default)]
pub struct UnitFile {
    by_manager: BTreeMap<String, String>,
}

impl UnitFile {
    /// The state to apply, and the managers standing behind it.
    ///
    /// The system manager is authoritative wherever it answered. Otherwise
    /// the user managers have to agree: an Entry holds one enablement for one
    /// path, so where two users report different states for the same file
    /// there is no answer to give, and the Entry keeps the inferred one.
    fn agreed(&self) -> Option<(&str, Vec<&str>)> {
        if let Some(state) = self.by_manager.get(SYSTEM) {
            return Some((state, vec![SYSTEM]));
        }
        let first = self.by_manager.values().next()?;
        if self.by_manager.values().any(|s| s != first) {
            return None;
        }
        Some((first, self.by_manager.keys().map(String::as_str).collect()))
    }

    /// Every answer, spelled out. What an operator needs when they differ,
    /// and when they agree it still says who was asked.
    fn breakdown(&self) -> String {
        self.by_manager.iter().map(|(m, s)| format!("{m}={s}")).collect::<Vec<_>>().join(", ")
    }
}

pub struct Manager {
    /// Keyed by the unit file's path on disk, which is what ListUnitFiles
    /// returns and what the collectors recorded as `source`.
    by_path: BTreeMap<PathBuf, UnitFile>,
    /// Keyed by manager and unit name: runtime state for units a manager has
    /// loaded. The name alone does not identify a unit — the system manager
    /// and a user manager may each have a syncthing.service, and they are
    /// different units with different runtime states.
    active: BTreeMap<(String, String), (String, String)>,
}

impl Manager {
    /// Asks the system manager and every user manager that is running, with a
    /// deadline on each phase. Returns None where there is nothing to ask —
    /// an offline root, a container without systemd, a socket we may not
    /// open, or a bus that does not answer — all of which leave the inferred
    /// answer and its DegradedEnablement flag in place.
    ///
    /// The deadline is not a nicety. Enrichment runs after every collector
    /// has finished, so a bus that accepts a connection and then never
    /// replies would hang a completed scan just before it printed anything.
    pub fn query(root: &Root) -> Option<Manager> {
        if !root.is_live() {
            return None;
        }
        let mut merged = with_deadline(QUERY_DEADLINE, || Manager::from_bus(SYSTEM, &connect_system()?));

        let buses = user_buses(root);
        if !buses.is_empty() {
            if let Some(users) = with_deadline(USER_DEADLINE, move || query_users(buses)) {
                match &mut merged {
                    Some(system) => system.merge(users),
                    None => merged = Some(users),
                }
            }
        }
        merged
    }
}

/// Long enough for a loaded machine with thousands of units, short enough
/// that an operator does not think the tool has died.
const QUERY_DEADLINE: Duration = Duration::from_secs(20);

/// The whole user phase, however many accounts have a session. Connecting to
/// a live bus on the same machine costs milliseconds, so this is not an
/// allowance to spend but a ceiling on what a bus that accepts a connection
/// and then stalls can cost: fifty sessions cannot become fifty timeouts.
const USER_BUDGET: Duration = Duration::from_secs(5);

/// What the user phase gets before it is abandoned. It stops starting new
/// queries at USER_BUDGET, so the extra is only there to let a query already
/// in flight finish and hand back what the earlier users answered.
const USER_DEADLINE: Duration = Duration::from_secs(7);

/// Runs one query on a thread and abandons it at the deadline.
///
/// The thread is left to its fate if it overruns: this is a one-shot scan,
/// and a stuck D-Bus connection must not outlive its usefulness.
fn with_deadline<T: Send + 'static>(
    deadline: Duration,
    f: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(deadline).ok().flatten()
}

/// Asks each user manager in turn, all of them inside one budget.
///
/// One thread for the lot, not one per user: a thread per account means
/// fifty simultaneous connections into a host that may already be under
/// stress, and fifty threads that cannot be joined when one of them wedges.
fn query_users(buses: Vec<(u32, String)>) -> Option<Manager> {
    let start = Instant::now();
    let mut merged: Option<Manager> = None;
    for (uid, address) in buses {
        // Tested before the connect rather than after it: what has to be
        // bounded is the time this pass can still start spending.
        if start.elapsed() >= USER_BUDGET {
            break;
        }
        let Some(conn) = connect_user(&address) else { continue };
        let Some(answers) = Manager::from_bus(&format!("user:{uid}"), &conn) else { continue };
        match &mut merged {
            Some(acc) => acc.merge(answers),
            None => merged = Some(answers),
        }
    }
    merged
}

/// The user managers worth asking. /run/user/<uid> exists only while a user
/// has a session, which is exactly when there is a manager to ask; a user
/// without one keeps the enablement the filesystem walk inferred.
///
/// Reaching another user's bus needs privilege. As root it works, as an
/// ordinary user it works for that user alone, and in both cases a refused
/// connection is silently one fewer answer.
fn user_buses(root: &Root) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    for ent in root.read_dir_optional("run/user").unwrap_or_default() {
        let Some(uid) = ent.name.to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let rel = format!("run/user/{uid}/bus");
        if !root.exists(&rel) {
            continue;
        }
        out.push((uid, format!("unix:path={}", root.abs(&rel).display())));
    }
    out
}

impl Manager {
    fn from_bus(id: &str, conn: &zbus::blocking::Connection) -> Option<Manager> {
        let mut by_path: BTreeMap<PathBuf, UnitFile> = BTreeMap::new();
        if let Ok(reply) = call(conn, "ListUnitFiles") {
            if let Ok(files) = reply.body().deserialize::<Vec<(String, String)>>() {
                for (path, state) in files {
                    by_path
                        .entry(PathBuf::from(path))
                        .or_default()
                        .by_manager
                        .insert(id.to_string(), state);
                }
            }
        }
        if by_path.is_empty() {
            return None;
        }

        let mut active = BTreeMap::new();
        if let Ok(reply) = call(conn, "ListUnits") {
            type Unit = (String, String, String, String, String, String, zbus::zvariant::OwnedObjectPath, u32, String, zbus::zvariant::OwnedObjectPath);
            if let Ok(units) = reply.body().deserialize::<Vec<Unit>>() {
                for u in units {
                    active.insert((id.to_string(), u.0), (u.3, u.4));
                }
            }
        }

        Some(Manager { by_path, active })
    }

    /// Folds another manager's answers in, keeping both where they cover the
    /// same path. Manager ids are unique, so nothing here can overwrite an
    /// answer — that decision belongs to `UnitFile::agreed`.
    fn merge(&mut self, other: Manager) {
        for (path, file) in other.by_path {
            self.by_path.entry(path).or_default().by_manager.extend(file.by_manager);
        }
        self.active.extend(other.active);
    }

    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }
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
fn connect_system() -> Option<zbus::blocking::Connection> {
    zbus::blocking::Connection::system().ok()
}

/// A user manager answers on that user's bus. Its private socket at
/// /run/user/<uid>/systemd/private is the same trap as the system one and is
/// left alone for the same reason.
fn connect_user(address: &str) -> Option<zbus::blocking::Connection> {
    zbus::blocking::connection::Builder::address(address).ok()?.build().ok()
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
/// some manager knows about. Everything else keeps its inferred value and its
/// DegradedEnablement flag, which is the honest outcome.
pub fn apply(manager: &Manager, entries: &mut [Entry]) -> usize {
    let mut answered = 0;
    for e in entries {
        if !matches!(e.kind, Kind::SystemdUnit | Kind::SystemdTimer) {
            continue;
        }
        let Some(file) = manager.by_path.get(&e.source) else { continue };

        if file.by_manager.len() > 1 {
            e.note("enablement_managers", file.breakdown());
        }
        let Some((state, from)) = file.agreed() else { continue };

        // A user's bus socket lives in that user's own runtime directory, so
        // a compromised account can run something that answers there and says
        // whatever it likes. A user manager is believed about units the
        // collector put in a user scope; a system unit's enablement comes
        // from the system manager or it stays inferred.
        if !file.by_manager.contains_key(SYSTEM)
            && !e.raw.get("scope").is_some_and(|s| s.starts_with("user"))
        {
            continue;
        }

        // Keeping the inferred answer is what makes the symlink-resolution
        // path testable. It is the offline implementation, and a live host
        // is the only place its answers can be checked against systemd's.
        if e.enabled != Enablement::Unknown {
            e.note("inferred_enablement", e.enabled.as_str());
        }
        e.enabled = enablement_of(state);
        e.note("unit_file_state", state);
        e.note("enablement_from", from.join(", "));
        e.flags.retain(|f| *f != Flag::DegradedEnablement);
        answered += 1;

        // Runtime state belongs to one manager. Where several agreed about
        // the unit file, they are still running it separately and there is no
        // single active state to report.
        if let [only] = from[..] {
            if let Some((active, sub)) = manager.active.get(&(only.to_string(), e.name.clone())) {
                e.note("active_state", active);
                e.note("sub_state", sub);
            }
        }

        // A generated unit was written by a systemd generator, which is
        // itself a persistence mechanism and a separate entry. Saying so
        // here is what lets an operator connect the two.
        if state == "generated" {
            e.note("generated", "true");
            if matches!(e.provenance, Provenance::Unpackaged | Provenance::Unknown) {
                e.provenance = Provenance::GeneratedBy { by: "systemd-generator".into() };
                // The unit file was written by a generator; what it runs is a
                // separate file with its own verdict. An Unpackaged flag that
                // came from the target is still true and stays.
                if e.raw.get("target_provenance").map(String::as_str) != Some("unpackaged") {
                    e.flags.retain(|f| *f != Flag::Unpackaged);
                }
            }
        }
    }
    answered
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One path's answers, as the managers gave them.
    fn answers(pairs: &[(&str, &str)]) -> UnitFile {
        UnitFile {
            by_manager: pairs.iter().map(|(m, s)| (m.to_string(), s.to_string())).collect(),
        }
    }

    /// A manager that answered about unit files and is running nothing.
    fn manager_of(files: Vec<(&str, UnitFile)>) -> Manager {
        Manager {
            by_path: files.into_iter().map(|(p, f)| (PathBuf::from(p), f)).collect(),
            active: BTreeMap::new(),
        }
    }

    fn user_unit(source: &str, name: &str, scope: &str) -> Entry {
        let mut e = Entry::new(Kind::SystemdUnit, source, name);
        e.enabled = Enablement::Disabled;
        e.flag(Flag::DegradedEnablement);
        e.note("scope", scope);
        e
    }

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
            by_path: [(PathBuf::from("/etc/systemd/system/evil.service"), answers(&[("system", "enabled")]))]
                .into_iter()
                .collect(),
            active: [(
                ("system".to_string(), "evil.service".to_string()),
                ("active".to_string(), "running".to_string()),
            )]
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
        assert_eq!(e.raw["enablement_from"], "system");
    }

    #[test]
    fn the_inferred_answer_is_kept_so_the_offline_path_can_be_checked() {
        let mut e = Entry::new(Kind::SystemdUnit, "/usr/lib/systemd/system/a.service", "a.service");
        e.enabled = Enablement::Disabled;
        e.flag(Flag::DegradedEnablement);

        let manager = manager_of(vec![("/usr/lib/systemd/system/a.service", answers(&[("system", "static")]))]);
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

        let manager = manager_of(vec![("/etc/systemd/system/other.service", answers(&[("system", "enabled")]))]);

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

        let manager = manager_of(vec![("/run/systemd/generator/x.mount", answers(&[("system", "generated")]))]);

        let mut entries = vec![e];
        apply(&manager, &mut entries);
        assert!(!entries[0].has_flag(Flag::Unpackaged));
        assert_eq!(entries[0].raw["generated"], "true");
        assert!(matches!(&entries[0].provenance, Provenance::GeneratedBy { by } if by == "systemd-generator"));
    }

    #[test]
    fn a_generated_unit_keeps_the_unpackaged_flag_its_target_earned() {
        let mut e = Entry::new(Kind::SystemdUnit, "/run/systemd/generator/x.service", "x.service");
        e.provenance = Provenance::Unpackaged;
        e.note("target_provenance", "unpackaged");
        e.flag(Flag::Unpackaged);

        let manager = manager_of(vec![("/run/systemd/generator/x.service", answers(&[("system", "generated")]))]);
        let mut entries = vec![e];
        apply(&manager, &mut entries);
        assert!(matches!(&entries[0].provenance, Provenance::GeneratedBy { .. }));
        assert!(entries[0].has_flag(Flag::Unpackaged), "what the unit runs is still unpackaged");
    }

    #[test]
    fn a_users_own_manager_answers_for_that_users_units() {
        let e = user_unit("/home/alice/.config/systemd/user/evil.service", "evil.service", "user:alice");

        let manager = Manager {
            by_path: [(
                PathBuf::from("/home/alice/.config/systemd/user/evil.service"),
                answers(&[("user:1000", "enabled")]),
            )]
            .into_iter()
            .collect(),
            active: [(
                ("user:1000".to_string(), "evil.service".to_string()),
                ("active".to_string(), "running".to_string()),
            )]
            .into_iter()
            .collect(),
        };

        let mut entries = vec![e];
        assert_eq!(apply(&manager, &mut entries), 1);
        let e = &entries[0];
        assert_eq!(e.enabled, Enablement::Enabled);
        assert!(!e.has_flag(Flag::DegradedEnablement));
        assert_eq!(e.raw["enablement_from"], "user:1000");
        assert_eq!(e.raw["inferred_enablement"], "disabled");
        assert_eq!(e.raw["active_state"], "active");
    }

    #[test]
    fn a_user_with_no_running_manager_keeps_the_inferred_answer_and_its_flag() {
        // bob has unit files and no session. alice's manager cannot speak
        // for them, and the walk's answer is all there is.
        let alice = user_unit("/home/alice/.config/systemd/user/x.service", "x.service", "user:alice");
        let bob = user_unit("/home/bob/.config/systemd/user/x.service", "x.service", "user:bob");

        let manager = manager_of(vec![(
            "/home/alice/.config/systemd/user/x.service",
            answers(&[("user:1000", "enabled")]),
        )]);

        let mut entries = vec![alice, bob];
        assert_eq!(apply(&manager, &mut entries), 1);
        assert_eq!(entries[1].enabled, Enablement::Disabled);
        assert!(entries[1].has_flag(Flag::DegradedEnablement));
        assert!(!entries[1].raw.contains_key("enablement_from"));
    }

    #[test]
    fn two_managers_disagreeing_about_one_file_answer_for_neither() {
        // /usr/lib/systemd/user is on every user manager's search path, and
        // one entry cannot hold two enablements. Both answers are recorded;
        // neither is applied.
        let e = user_unit("/usr/lib/systemd/user/shared.service", "shared.service", "user");

        let manager = manager_of(vec![(
            "/usr/lib/systemd/user/shared.service",
            answers(&[("user:1000", "enabled"), ("user:1001", "disabled")]),
        )]);

        let mut entries = vec![e];
        assert_eq!(apply(&manager, &mut entries), 0);
        let e = &entries[0];
        assert_eq!(e.enabled, Enablement::Disabled, "the inferred answer stands");
        assert!(e.has_flag(Flag::DegradedEnablement));
        assert_eq!(e.raw["enablement_managers"], "user:1000=enabled, user:1001=disabled");
        assert!(!e.raw.contains_key("enablement_from"));
    }

    #[test]
    fn two_managers_agreeing_about_one_file_both_answer_for_it() {
        let e = user_unit("/usr/lib/systemd/user/shared.service", "shared.service", "user");

        let manager = Manager {
            by_path: [(
                PathBuf::from("/usr/lib/systemd/user/shared.service"),
                answers(&[("user:1000", "enabled"), ("user:1001", "enabled")]),
            )]
            .into_iter()
            .collect(),
            active: [(
                ("user:1000".to_string(), "shared.service".to_string()),
                ("active".to_string(), "running".to_string()),
            )]
            .into_iter()
            .collect(),
        };

        let mut entries = vec![e];
        assert_eq!(apply(&manager, &mut entries), 1);
        let e = &entries[0];
        assert_eq!(e.enabled, Enablement::Enabled);
        assert_eq!(e.raw["enablement_from"], "user:1000, user:1001");
        assert_eq!(e.raw["enablement_managers"], "user:1000=enabled, user:1001=enabled");
        assert!(
            !e.raw.contains_key("active_state"),
            "one of two managers running it is not the entry's runtime state"
        );
    }

    #[test]
    fn the_system_manager_outranks_a_user_manager_on_the_same_path() {
        let mut e = Entry::new(Kind::SystemdUnit, "/etc/systemd/system/evil.service", "evil.service");
        e.enabled = Enablement::Disabled;
        e.flag(Flag::DegradedEnablement);
        e.note("scope", "system");

        let manager = manager_of(vec![(
            "/etc/systemd/system/evil.service",
            answers(&[("system", "enabled"), ("user:1337", "masked")]),
        )]);

        let mut entries = vec![e];
        assert_eq!(apply(&manager, &mut entries), 1);
        assert_eq!(entries[0].enabled, Enablement::Enabled);
        assert_eq!(entries[0].raw["enablement_from"], "system");
        assert_eq!(entries[0].raw["enablement_managers"], "system=enabled, user:1337=masked");
    }

    #[test]
    fn a_user_manager_may_not_speak_for_a_system_unit() {
        // The bus socket sits in the user's own runtime directory, so this is
        // an answer an unprivileged account can fabricate. Taking it would
        // let that account clear DegradedEnablement off a planted root unit.
        let mut e = Entry::new(Kind::SystemdUnit, "/etc/systemd/system/planted.service", "planted.service");
        e.enabled = Enablement::Enabled;
        e.flag(Flag::DegradedEnablement);
        e.note("scope", "system");

        let manager = manager_of(vec![(
            "/etc/systemd/system/planted.service",
            answers(&[("user:1337", "disabled")]),
        )]);

        let mut entries = vec![e];
        assert_eq!(apply(&manager, &mut entries), 0);
        assert_eq!(entries[0].enabled, Enablement::Enabled);
        assert!(entries[0].has_flag(Flag::DegradedEnablement));
    }

    #[test]
    fn user_managers_are_discovered_from_the_runtime_directories_that_exist() {
        let dir = std::env::temp_dir().join(format!("unbidden-dbus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for rel in ["run/user/1000", "run/user/1001", "run/user/nobody"] {
            std::fs::create_dir_all(dir.join(rel)).unwrap();
        }
        // A session with a bus, a session without one, and a name that is not
        // a uid at all — /run/user is writable by nothing but systemd, but a
        // parser that trusts its contents is still a parser that panics.
        std::fs::write(dir.join("run/user/1000/bus"), b"").unwrap();
        std::fs::write(dir.join("run/user/nobody/bus"), b"").unwrap();

        let root = Root::at(&dir).unwrap();
        let found = user_buses(&root);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 1000);
        assert_eq!(found[0].1, format!("unix:path={}/run/user/1000/bus", dir.display()));

        // Nothing is asked of an offline root, whatever it contains.
        assert!(Manager::query(&root).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
