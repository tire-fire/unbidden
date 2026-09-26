//! Baseline comparison.
//!
//! Stable entry identity is what makes this worth having: a backdoor that
//! rewrites its own ExecStart line shows up as one changed entry naming
//! `command` and `target_sha256`, not as a removal and an unrelated addition
//! that an operator has to notice are the same thing.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::entry::Entry;
use crate::scan::{CollectorStatus, Scan, Status};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "delta", rename_all = "lowercase")]
pub enum Delta {
    Added,
    Removed,
    Changed { fields: Vec<&'static str> },
    Unchanged,
    /// Would be `would_be`, but its collector did not see the same things
    /// both times, so the difference may be the coverage and not the host.
    Uncertain { would_be: &'static str, fields: Vec<&'static str>, because: String },
}

impl Delta {
    pub fn label(&self) -> &'static str {
        match self {
            Delta::Added => "added",
            Delta::Removed => "removed",
            Delta::Changed { .. } => "changed",
            Delta::Unchanged => "unchanged",
            Delta::Uncertain { .. } => "uncertain",
        }
    }
}

#[derive(Debug)]
pub struct Diffed {
    pub entry: Entry,
    pub delta: Delta,
}

/// Comparing two scans that did not see the same things produces fiction.
/// A baseline taken while the rpm collector failed would report every
/// RPM-owned entry as newly appeared, and a baseline taken unprivileged
/// would report every root-owned one as removed.
pub fn comparable(baseline: &Scan, current: &Scan) -> Result<(), String> {
    if baseline.header.deep != current.header.deep {
        return Err(format!(
            "baseline was taken {} and this scan {}; a deep scan and a shallow one are not comparable",
            depth(baseline.header.deep),
            depth(current.header.deep)
        ));
    }
    if baseline.header.privileged != current.header.privileged {
        return Err(format!(
            "baseline was taken {} and this scan {}; run both the same way",
            privilege(baseline.header.privileged),
            privilege(current.header.privileged)
        ));
    }

    if baseline.header.enablement != current.header.enablement {
        return Err(format!(
            "baseline enablement came from {} and this scan's from {}; \
             every unit would appear to have changed",
            baseline.header.enablement, current.header.enablement
        ));
    }

    // A stage that panicked left its facts off some entries, so its flags
    // would read as changes that never happened on the host.
    for (when, s) in [("the baseline", baseline), ("this scan", current)] {
        if !s.header.enrichment_failures.is_empty() {
            return Err(format!(
                "enrichment failed in {when}, so its provenance and flags are incomplete:\n  {}",
                s.header.enrichment_failures.join("\n  ")
            ));
        }
    }

    Ok(())
}

/// What one collector could see: everything, everything but some paths, or
/// nothing at all.
#[derive(Clone, Debug, PartialEq)]
enum Coverage {
    All,
    AllBut(BTreeSet<String>),
    Nothing,
}

impl Coverage {
    fn of(s: Option<&CollectorStatus>) -> Coverage {
        match s.map(|c| &c.status) {
            Some(Status::Complete) => Coverage::All,
            Some(Status::Partial { unreadable }) => Coverage::AllBut(unreadable.iter().cloned().collect()),
            _ => Coverage::Nothing,
        }
    }

    /// Whether this saw at least everything `other` saw.
    fn covers(&self, other: &Coverage) -> bool {
        match (self, other) {
            (Coverage::All, _) | (_, Coverage::Nothing) => true,
            (Coverage::AllBut(mine), Coverage::AllBut(theirs)) => mine.is_subset(theirs),
            _ => false,
        }
    }
}

/// Which of a collector's differences can be believed. Where the baseline
/// saw everything the current scan saw, anything new is new; where the
/// current scan saw everything the baseline saw, anything gone is gone.
/// A change to an entry both scans hold is believed only when both saw the
/// same things: an unreadable drop-in changes what a unit runs.
struct Trust {
    added: bool,
    removed: bool,
    changed: bool,
    because: String,
}

/// Per collector, how far its differences can be trusted, for the ones
/// whose coverage moved. A collector absent from this map saw the same
/// things both times.
pub fn coverage_changes(baseline: &Scan, current: &Scan) -> BTreeMap<String, String> {
    trust(baseline, current).into_iter().map(|(name, t)| (name, t.because)).collect()
}

fn trust(baseline: &Scan, current: &Scan) -> BTreeMap<String, Trust> {
    let by_name = |s: &Scan| -> BTreeMap<String, CollectorStatus> {
        s.header.collectors.iter().map(|c| (c.name.clone(), c.clone())).collect()
    };
    let (old, new) = (by_name(baseline), by_name(current));
    let mut out = BTreeMap::new();
    for name in old.keys().chain(new.keys()).collect::<BTreeSet<_>>() {
        let (then, now) = (Coverage::of(old.get(name)), Coverage::of(new.get(name)));
        let (narrowed, widened) = (then.covers(&now), now.covers(&then));
        if narrowed && widened {
            continue;
        }
        let status = |c: Option<&CollectorStatus>| c.map_or("absent", |c| kind_of(&c.status));
        let mut because = format!("{name}: {} then, {} now", status(old.get(name)), status(new.get(name)));
        let unreadable = |c: Option<&CollectorStatus>| match c.map(|c| &c.status) {
            Some(Status::Partial { unreadable }) => unreadable.clone(),
            _ => Vec::new(),
        };
        let (was, is) = (unreadable(old.get(name)), unreadable(new.get(name)));
        let fresh: Vec<&String> = is.iter().filter(|u| !was.contains(u)).collect();
        let cleared: Vec<&String> = was.iter().filter(|u| !is.contains(u)).collect();
        if !fresh.is_empty() {
            because.push_str(&format!("; newly unreadable: {}", fresh.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
        }
        if !cleared.is_empty() {
            because.push_str(&format!("; readable again: {}", cleared.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
        }
        out.insert(name.clone(), Trust { added: narrowed, removed: widened, changed: false, because });
    }
    out
}

fn depth(deep: bool) -> &'static str {
    if deep { "with --deep" } else { "without --deep" }
}

fn privilege(root: bool) -> &'static str {
    if root { "as root" } else { "unprivileged" }
}

fn kind_of(s: &Status) -> &'static str {
    match s {
        Status::Complete => "complete",
        Status::Partial { .. } => "partial",
        Status::Skipped { .. } => "skipped",
        Status::Failed { .. } => "failed",
    }
}

/// Duplicate ids would silently overwrite one another in any map keyed by
/// id, and the row that vanishes could be the attacker's. Refuse instead.
fn index(scan: &Scan, which: &str) -> Result<BTreeMap<String, Entry>, String> {
    let mut out: BTreeMap<String, Entry> = BTreeMap::new();
    for e in &scan.entries {
        if let Some(first) = out.insert(e.id.clone(), e.clone()) {
            return Err(format!(
                "duplicate entry id in the {which}: {} is both {} ({}) and {} ({}). \
                 This is a collector defect or a deliberate collision; the diff will not guess.",
                e.short_id(),
                first.name,
                first.source.display(),
                e.name,
                e.source.display()
            ));
        }
    }
    Ok(out)
}

pub fn diff(baseline: &Scan, current: &Scan) -> Result<Vec<Diffed>, String> {
    comparable(baseline, current)?;
    let trust = trust(baseline, current);
    // A baseline written before entries named their collector cannot say
    // which differences a coverage change touches, so it refuses as every
    // baseline used to.
    if !trust.is_empty() && baseline.entries.iter().any(|e| e.collector.is_none()) {
        let because: Vec<&str> = trust.values().map(|t| t.because.as_str()).collect();
        return Err(format!(
            "collector coverage differs, and this baseline predates per-collector comparison; \
             take a new baseline:\n  {}",
            because.join("\n  ")
        ));
    }
    let mut old = index(baseline, "baseline")?;
    let new = index(current, "current scan")?;

    // The delta an entry has, or Uncertain where its collector's coverage
    // moved in a way that could have produced it.
    let judged = |entry: &Entry, delta: Delta| -> Delta {
        let Some(t) = entry.collector.as_ref().and_then(|c| trust.get(c)) else { return delta };
        let (trusted, would_be, fields) = match &delta {
            Delta::Added => (t.added, "added", Vec::new()),
            Delta::Removed => (t.removed, "removed", Vec::new()),
            Delta::Changed { fields } => (t.changed, "changed", fields.clone()),
            _ => return delta,
        };
        if trusted { delta } else { Delta::Uncertain { would_be, fields, because: t.because.clone() } }
    };

    let mut out = Vec::new();
    for (id, entry) in new {
        match old.remove(&id) {
            None => {
                let delta = judged(&entry, Delta::Added);
                out.push(Diffed { entry, delta });
            }
            Some(before) => {
                let fields = changed_fields(&before, &entry);
                // A timestamp that moved on its own is not a change. systemd
                // rewrites every generated unit on each daemon-reload, so
                // reporting mtime alone would fill a diff with rows whose
                // contents are byte-identical — and a diff nobody trusts is
                // a diff nobody reads. The field is still in the record and
                // in `explain` for anyone who wants to cluster on it.
                let substantive: Vec<&'static str> =
                    fields.iter().copied().filter(|f| *f != "mtime").collect();
                let delta = if substantive.is_empty() {
                    Delta::Unchanged
                } else {
                    judged(&entry, Delta::Changed { fields })
                };
                out.push(Diffed { entry, delta });
            }
        }
    }
    // Whatever the baseline still holds was not seen this time.
    for (_, entry) in old {
        let delta = judged(&entry, Delta::Removed);
        out.push(Diffed { entry, delta });
    }

    out.sort_by(|a, b| (a.entry.kind, &a.entry.source, &a.entry.name).cmp(&(b.entry.kind, &b.entry.source, &b.entry.name)));
    Ok(out)
}

fn changed_fields(before: &Entry, after: &Entry) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut check = |name: &'static str, differs: bool| {
        if differs {
            out.push(name);
        }
    };
    check("command", before.command != after.command);
    check("target_path", before.target_path != after.target_path);
    check("target_sha256", before.target_sha256 != after.target_sha256);
    check("enabled", before.enabled != after.enabled);
    check("trigger", before.trigger != after.trigger);
    check("principal", before.principal != after.principal);
    check("owner_uid", before.owner_uid != after.owner_uid);
    check("mode", before.mode != after.mode);
    check("mtime", before.mtime != after.mtime);
    check("provenance", before.provenance != after.provenance);
    check("flags", {
        let mut a = before.flags.clone();
        let mut b = after.flags.clone();
        a.sort();
        b.sort();
        a != b
    });
    // Collector notes prefixed `live.` describe the machine's current state
    // rather than its configuration — a loaded module's reference count, its
    // dependants. They move on their own, and a diff that reports them is a
    // diff whose real findings are buried.
    fn settled(e: &Entry) -> BTreeMap<&String, &String> {
        e.raw.iter().filter(|(k, _)| !k.starts_with("live.")).collect()
    }
    check("raw", settled(before) != settled(after));
    out
}

/// The entry, plus its delta, as one JSON object. Additive: every field of
/// the entry schema is still where a consumer expects it.
pub fn to_json(d: &Diffed) -> serde_json::Value {
    let mut value = serde_json::to_value(&d.entry).unwrap_or(serde_json::Value::Null);
    if let Some(map) = value.as_object_mut() {
        map.insert("delta".into(), serde_json::Value::String(d.delta.label().into()));
        match &d.delta {
            Delta::Changed { fields } => {
                map.insert("changed".into(), serde_json::json!(fields));
            }
            Delta::Uncertain { would_be, fields, because } => {
                map.insert("would_be".into(), serde_json::json!(would_be));
                if !fields.is_empty() {
                    map.insert("changed".into(), serde_json::json!(fields));
                }
                map.insert("uncertain_because".into(), serde_json::json!(because));
            }
            _ => {}
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Enablement, Kind};
    use crate::scan::{Header, SCHEMA_VERSION};

    fn header() -> Header {
        Header {
            unbidden_version: "0.1.0".into(),
            schema_version: SCHEMA_VERSION,
            scan_time: 0,
            hostname: "h".into(),
            kernel: "k".into(),
            distro_id: "debian".into(),
            distro_version: "12".into(),
                distro_like: String::new(),
            root: "/".into(),
            live: true,
            deep: false,
            privileged: true,
            enablement: crate::scan::inferred(),
            collectors: vec![CollectorStatus {
                name: "systemd".into(),
                entries: 1,
                status: Status::Complete,
                truncated: Vec::new(),
            }],
            enrichment_failures: Vec::new(),
        }
    }

    fn unit(name: &str, command: &[u8]) -> Entry {
        let mut e = Entry::new(Kind::SystemdUnit, format!("/etc/systemd/system/{name}"), name);
        e.command = Some(command.to_vec());
        e.enabled = Enablement::Enabled;
        e.collector = Some("systemd".into());
        e
    }

    fn scan_of(entries: Vec<Entry>) -> Scan {
        Scan { header: header(), entries }
    }

    #[test]
    fn a_rewritten_backdoor_is_one_changed_entry_not_two() {
        let before = scan_of(vec![unit("evil.service", b"/tmp/stage1")]);
        let mut after_entry = unit("evil.service", b"/tmp/stage2");
        after_entry.target_sha256 = Some("deadbeef".into());
        let after = scan_of(vec![after_entry]);

        let d = diff(&before, &after).unwrap();
        assert_eq!(d.len(), 1, "identity survived the edit");
        match &d[0].delta {
            Delta::Changed { fields } => {
                assert!(fields.contains(&"command"));
                assert!(fields.contains(&"target_sha256"));
            }
            other => panic!("expected a change naming its fields, got {other:?}"),
        }
    }

    #[test]
    fn a_timestamp_that_moved_on_its_own_is_not_a_change() {
        let before = scan_of(vec![unit("gen.service", b"/usr/bin/x")]);
        let mut touched = unit("gen.service", b"/usr/bin/x");
        touched.mtime = Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000));
        let after = scan_of(vec![touched.clone()]);
        assert_eq!(diff(&before, &after).unwrap()[0].delta, Delta::Unchanged);

        // But an mtime that moved alongside real content still reports both,
        // because the pair together is what an analyst wants to see.
        let mut edited = touched;
        edited.command = Some(b"/tmp/evil".to_vec());
        let after = scan_of(vec![edited]);
        match &diff(&before, &after).unwrap()[0].delta {
            Delta::Changed { fields } => {
                assert!(fields.contains(&"command"));
                assert!(fields.contains(&"mtime"));
            }
            other => panic!("expected a change, got {other:?}"),
        }
    }

    #[test]
    fn live_kernel_state_that_moves_on_its_own_is_not_a_change() {
        let mut before = unit("i915", b"");
        before.raw.insert("live.refcount".into(), "12".into());
        before.raw.insert("directive".into(), "loaded".into());
        let mut after = before.clone();
        after.raw.insert("live.refcount".into(), "19".into());
        assert_eq!(diff(&scan_of(vec![before.clone()]), &scan_of(vec![after])).unwrap()[0].delta, Delta::Unchanged);

        // A note that is not live state still counts.
        let mut edited = before.clone();
        edited.raw.insert("directive".into(), "install".into());
        match &diff(&scan_of(vec![before]), &scan_of(vec![edited])).unwrap()[0].delta {
            Delta::Changed { fields } => assert!(fields.contains(&"raw")),
            other => panic!("expected a change, got {other:?}"),
        }
    }

    #[test]
    fn additions_removals_and_no_change_at_all() {
        let before = scan_of(vec![unit("a.service", b"/usr/bin/a"), unit("gone.service", b"/usr/bin/g")]);
        let after = scan_of(vec![unit("a.service", b"/usr/bin/a"), unit("new.service", b"/tmp/n")]);

        let d = diff(&before, &after).unwrap();
        let by: BTreeMap<&str, &Delta> = d.iter().map(|x| (x.entry.name.as_str(), &x.delta)).collect();
        assert_eq!(by["a.service"], &Delta::Unchanged);
        assert_eq!(by["new.service"], &Delta::Added);
        assert_eq!(by["gone.service"], &Delta::Removed);
    }

    #[test]
    fn scans_that_did_not_see_the_same_things_refuse_to_diff() {
        let before = scan_of(vec![unit("a.service", b"/usr/bin/a")]);

        let mut after = scan_of(vec![unit("a.service", b"/usr/bin/a")]);
        after.header.privileged = false;
        let err = diff(&before, &after).unwrap_err();
        assert!(err.contains("unprivileged"), "{err}");

        // A baseline written before entries named their collector cannot
        // tell which differences a coverage change touches.
        let mut old = scan_of(vec![unit("a.service", b"/usr/bin/a")]);
        old.entries[0].collector = None;
        let mut after = scan_of(vec![unit("a.service", b"/usr/bin/a")]);
        after.header.collectors[0].status = Status::Failed { error: "boom".into() };
        let err = diff(&old, &after).unwrap_err();
        assert!(err.contains("predates per-collector comparison") && err.contains("complete then, failed now"), "{err}");

        let mut after = scan_of(vec![unit("a.service", b"/usr/bin/a")]);
        after.header.deep = true;
        assert!(diff(&before, &after).unwrap_err().contains("deep"));

        let mut after = scan_of(vec![unit("a.service", b"/usr/bin/a")]);
        after.header.enablement = "systemd-dbus".into();
        assert_eq!(
            diff(&before, &after).unwrap_err(),
            "baseline enablement came from inferred and this scan's from systemd-dbus; \
             every unit would appear to have changed"
        );

        let mut after = scan_of(vec![unit("a.service", b"/usr/bin/a")]);
        after.header.enrichment_failures.push("provenance: rpm database: boom".into());
        let err = diff(&before, &after).unwrap_err();
        assert!(err.contains("enrichment failed in this scan"), "{err}");
        assert!(diff(&after, &before).unwrap_err().contains("enrichment failed in the baseline"));
    }

    #[test]
    fn a_duplicate_id_fails_loudly_instead_of_dropping_a_row() {
        let mut dup = unit("a.service", b"/usr/bin/a");
        dup.name = "b.service".into();
        let before = scan_of(vec![unit("a.service", b"/usr/bin/a")]);
        let after = scan_of(vec![unit("a.service", b"/usr/bin/a"), dup]);

        let err = diff(&before, &after).unwrap_err();
        assert!(err.contains("duplicate entry id"), "{err}");
    }

    #[test]
    fn the_delta_rides_along_with_every_field_of_the_entry() {
        let before = scan_of(vec![unit("evil.service", b"/tmp/stage1")]);
        let after = scan_of(vec![unit("evil.service", b"/tmp/stage2")]);
        let d = diff(&before, &after).unwrap();
        let json = to_json(&d[0]);
        assert_eq!(json["delta"], "changed");
        assert_eq!(json["changed"][0], "command");
        assert_eq!(json["kind"], "systemd_unit");
        assert_eq!(json["command"], "/tmp/stage2");
    }

    #[test]
    fn a_collector_that_saw_less_makes_only_its_own_differences_uncertain() {
        let partial = |unreadable: &[&str]| Status::Partial { unreadable: unreadable.iter().map(|s| s.to_string()).collect() };
        let dbus = |name: &str| {
            let mut e = Entry::new(Kind::DbusService, format!("/usr/share/dbus-1/system-services/{name}"), name);
            e.collector = Some("pkg".into());
            e
        };
        let scan = |entries: Vec<Entry>, systemd: Status| {
            let mut s = scan_of(entries);
            s.header.collectors[0].status = systemd;
            s.header.collectors.push(CollectorStatus { name: "pkg".into(), entries: 0, status: Status::Complete, truncated: Vec::new() });
            s
        };
        let delta = |d: &[Diffed], name: &str| d.iter().find(|x| x.entry.name == name).unwrap().delta.clone();

        // The CI flake: systemd went partial after a plant, and the planted
        // D-Bus service, another collector's, must still read as added.
        let before = scan(vec![unit("gone.service", b"/a"), unit("edited.service", b"/a"), unit("same.service", b"/a")], Status::Complete);
        let after = scan(
            vec![unit("edited.service", b"/b"), unit("same.service", b"/a"), unit("new.service", b"/a"), dbus("org.evil.service")],
            partial(&["etc/systemd/system/x.service: permission denied"]),
        );
        let d = diff(&before, &after).unwrap();
        assert_eq!(delta(&d, "org.evil.service"), Delta::Added, "another collector's finding is untouched");
        assert_eq!(delta(&d, "new.service"), Delta::Added, "the baseline saw everything, so what is new is new");
        assert_eq!(delta(&d, "same.service"), Delta::Unchanged);
        let Delta::Uncertain { would_be, because, .. } = delta(&d, "gone.service") else { panic!() };
        assert_eq!(would_be, "removed", "it may only be unreadable now");
        assert!(because.contains("systemd: complete then, partial now") && because.contains("newly unreadable: etc/systemd/system/x.service"), "{because}");
        let Delta::Uncertain { would_be, fields, .. } = delta(&d, "edited.service") else { panic!() };
        assert_eq!((would_be, fields), ("changed", vec!["command"]), "a drop-in it could not read changes what a unit runs");
        assert_eq!(coverage_changes(&before, &after).len(), 1);

        // The other way round: removals are believed, additions are not.
        let d = diff(&after, &before).unwrap();
        assert_eq!(delta(&d, "new.service"), Delta::Removed);
        assert!(matches!(delta(&d, "gone.service"), Delta::Uncertain { would_be: "added", .. }));
        assert_eq!(delta(&d, "org.evil.service"), Delta::Removed);

        // Unreadable in different places each time: nothing is believed.
        let a = scan(vec![unit("x.service", b"/a")], partial(&["one"]));
        let b = scan(vec![unit("y.service", b"/a")], partial(&["two"]));
        let d = diff(&a, &b).unwrap();
        assert!(matches!(delta(&d, "x.service"), Delta::Uncertain { would_be: "removed", .. }));
        assert!(matches!(delta(&d, "y.service"), Delta::Uncertain { would_be: "added", .. }));

        // The same unreadable paths both times: comparable as ever.
        let a = scan(vec![unit("x.service", b"/a")], partial(&["one"]));
        let b = scan(vec![unit("y.service", b"/a")], partial(&["one"]));
        assert!(coverage_changes(&a, &b).is_empty());
        assert_eq!(delta(&diff(&a, &b).unwrap(), "y.service"), Delta::Added);
    }
}
