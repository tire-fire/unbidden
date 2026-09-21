//! Baseline comparison.
//!
//! Stable entry identity is what makes this worth having: a backdoor that
//! rewrites its own ExecStart line shows up as one changed entry naming
//! `command` and `target_sha256`, not as a removal and an unrelated addition
//! that an operator has to notice are the same thing.

use std::collections::BTreeMap;

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
}

impl Delta {
    pub fn label(&self) -> &'static str {
        match self {
            Delta::Added => "added",
            Delta::Removed => "removed",
            Delta::Changed { .. } => "changed",
            Delta::Unchanged => "unchanged",
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

    let by_name = |s: &Scan| -> BTreeMap<String, CollectorStatus> {
        s.header.collectors.iter().map(|c| (c.name.clone(), c.clone())).collect()
    };
    let (old, new) = (by_name(baseline), by_name(current));

    let mut problems = Vec::new();
    for name in old.keys().chain(new.keys()).collect::<std::collections::BTreeSet<_>>() {
        match (old.get(name), new.get(name)) {
            (Some(a), Some(b)) if kind_of(&a.status) != kind_of(&b.status) => problems.push(format!(
                "{name}: {} then, {} now",
                kind_of(&a.status),
                kind_of(&b.status)
            )),
            (Some(_), None) => problems.push(format!("{name}: present in the baseline, absent now")),
            (None, Some(_)) => problems.push(format!("{name}: absent from the baseline, present now")),
            _ => {}
        }
    }
    if !problems.is_empty() {
        return Err(format!("collector coverage differs, so the scans are not comparable:\n  {}", problems.join("\n  ")));
    }
    Ok(())
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
    let mut old = index(baseline, "baseline")?;
    let new = index(current, "current scan")?;

    let mut out = Vec::new();
    for (id, entry) in new {
        match old.remove(&id) {
            None => out.push(Diffed { entry, delta: Delta::Added }),
            Some(before) => {
                let fields = changed_fields(&before, &entry);
                let delta = if fields.is_empty() { Delta::Unchanged } else { Delta::Changed { fields } };
                out.push(Diffed { entry, delta });
            }
        }
    }
    // Whatever the baseline still holds was not seen this time.
    for (_, entry) in old {
        out.push(Diffed { entry, delta: Delta::Removed });
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
    check("raw", before.raw != after.raw);
    out
}

/// The entry, plus its delta, as one JSON object. Additive: every field of
/// the entry schema is still where a consumer expects it.
pub fn to_json(d: &Diffed) -> serde_json::Value {
    let mut value = serde_json::to_value(&d.entry).unwrap_or(serde_json::Value::Null);
    if let Some(map) = value.as_object_mut() {
        map.insert("delta".into(), serde_json::Value::String(d.delta.label().into()));
        if let Delta::Changed { fields } = &d.delta {
            map.insert("changed".into(), serde_json::json!(fields));
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
            root: "/".into(),
            live: true,
            deep: false,
            privileged: true,
            collectors: vec![CollectorStatus {
                name: "systemd".into(),
                entries: 1,
                status: Status::Complete,
                truncated: Vec::new(),
            }],
        }
    }

    fn unit(name: &str, command: &[u8]) -> Entry {
        let mut e = Entry::new(Kind::SystemdUnit, format!("/etc/systemd/system/{name}"), name);
        e.command = Some(command.to_vec());
        e.enabled = Enablement::Enabled;
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

        let mut after = scan_of(vec![unit("a.service", b"/usr/bin/a")]);
        after.header.collectors[0].status = Status::Failed { error: "boom".into() };
        let err = diff(&before, &after).unwrap_err();
        assert!(err.contains("complete then, failed now"), "{err}");

        let mut after = scan_of(vec![unit("a.service", b"/usr/bin/a")]);
        after.header.deep = true;
        assert!(diff(&before, &after).unwrap_err().contains("deep"));
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
}
