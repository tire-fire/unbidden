//! Output. Suppression and filtering live here and nowhere else.
//!
//! The category error worth avoiding: hiding entries is a rendering decision,
//! never a scan decision. The scan always collects everything, --json always
//! emits everything, and the human table always says how many rows it hid.

use std::io::{self, IsTerminal, Write};

use crate::entry::{Entry, Flag, Kind, Trigger};
use crate::scan::{Scan, Status};

#[derive(Default, Clone)]
pub struct Filters {
    pub kinds: Vec<Kind>,
    pub triggers: Vec<Trigger>,
    pub flags: Vec<Flag>,
}

impl Filters {
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty() && self.triggers.is_empty() && self.flags.is_empty()
    }

    /// Explicit filters are a deliberate act by the operator and apply to
    /// every output form. Suppression is separate and applies only to the
    /// human table.
    pub fn keep(&self, e: &Entry) -> bool {
        (self.kinds.is_empty() || self.kinds.contains(&e.kind))
            && (self.triggers.is_empty() || self.triggers.contains(&e.trigger))
            && (self.flags.is_empty() || self.flags.iter().any(|f| e.has_flag(*f)))
    }
}

/// An entry is hidden by default when a package owns it, its contents still
/// match the manifest, and nothing else about it was worth remarking on.
///
/// A PackagedModified entry lives inside the packaged category and must never
/// be suppressed — it is the highest-signal finding the tool produces. Nor is
/// a packaged file that is world-writable or sitting behind a link into /tmp:
/// the spec's rule is "packaged and intact", and every other flag is a fact
/// the operator asked to see.
///
/// DegradedEnablement is the one exception. It says the enablement answer was
/// inferred rather than read from systemd, which is a caveat about the row,
/// not a finding about the host — and on a machine without a running systemd
/// it is set on every entry, which would suppress nothing at all.
pub fn suppressed(e: &Entry) -> bool {
    let quiet = e.flags.iter().all(|f| *f == Flag::DegradedEnablement);
    quiet && (e.provenance.is_packaged_intact() || from_package_database(e))
}

/// An entry read out of a package database rather than off the filesystem —
/// an rpm scriptlet, a file trigger. Its integrity is reported Unknown
/// because there is no file to hash: the record and the claim about it are
/// the same artifact.
///
/// Those are suppressed when a package owns them, which needs justifying
/// because §8 otherwise refuses to hide an unverified entry. The reasoning is
/// that this adds no exposure: §7 already takes the package database at its
/// word about who owns every file on the host, so an attacker who can edit it
/// to forge a scriptlet can equally edit it to claim their own binary is
/// shipped by glibc — which the existing rule would hide too. Refusing here
/// would buy nothing and cost the default view several hundred rows of vendor
/// scriptlets, which is the noise §8 exists to remove.
///
/// A scriptlet carrying any finding at all is still shown, so an encoded
/// payload or an unresolvable target in one reaches the operator.
fn from_package_database(e: &Entry) -> bool {
    e.raw.contains_key("read_from") && matches!(e.provenance, crate::entry::Provenance::Packaged { .. })
}

/// Newline-delimited: the header on the first line, then one entry per line,
/// so the stream survives truncation and can be tailed.
pub fn ndjson(w: &mut impl Write, scan: &Scan, filters: &Filters) -> io::Result<()> {
    serde_json::to_writer(&mut *w, &scan.header)?;
    w.write_all(b"\n")?;
    for e in scan.entries.iter().filter(|e| filters.keep(e)) {
        serde_json::to_writer(&mut *w, e)?;
        w.write_all(b"\n")?;
    }
    w.flush()
}

/// The array form, which is also the snapshot format of §9.
pub fn json_array(w: &mut impl Write, scan: &Scan, filters: &Filters) -> io::Result<()> {
    let filtered = Scan {
        header: scan.header.clone(),
        entries: scan.entries.iter().filter(|e| filters.keep(e)).cloned().collect(),
    };
    serde_json::to_writer_pretty(&mut *w, &filtered)?;
    w.write_all(b"\n")?;
    w.flush()
}

pub struct TableOpts {
    pub all: bool,
    pub width: usize,
}

pub fn table(w: &mut impl Write, scan: &Scan, filters: &Filters, opts: &TableOpts) -> io::Result<()> {
    banners(w, scan)?;

    let mut shown: Vec<&Entry> = Vec::new();
    let mut hidden = 0usize;
    for e in scan.entries.iter().filter(|e| filters.keep(e)) {
        if !opts.all && suppressed(e) {
            hidden += 1;
        } else {
            shown.push(e);
        }
    }

    let kind_w = width_of(shown.iter().map(|e| e.kind.as_str().len()), 12, 20);
    let name_w = width_of(shown.iter().map(|e| e.name.chars().count()), 12, 34);
    let flag_w = width_of(shown.iter().map(|e| flags_text(e).chars().count()), 5, 28);
    let fixed = 12 + 2 + kind_w + 2 + 8 + 2 + name_w + 2 + flag_w + 2;
    let cmd_w = opts.width.saturating_sub(fixed).max(12);

    writeln!(
        w,
        "{:<12}  {:<kind_w$}  {:<8}  {:<name_w$}  {:<flag_w$}  {}",
        "ID", "KIND", "ENABLED", "NAME", "FLAGS", "COMMAND"
    )?;

    for e in &shown {
        let command = match &e.command {
            Some(c) => String::from_utf8_lossy(c).replace(['\n', '\t', '\r'], " "),
            None => e
                .target_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| e.source.to_string_lossy().into_owned()),
        };
        writeln!(
            w,
            "{:<12}  {:<kind_w$}  {:<8}  {:<name_w$}  {:<flag_w$}  {}",
            e.short_id(),
            clip(e.kind.as_str(), kind_w),
            clip(e.enabled.as_str(), 8),
            clip(&e.name, name_w),
            clip(&flags_text(e), flag_w),
            clip(&command, cmd_w),
        )?;
    }

    writeln!(w)?;
    writeln!(w, "{} entries shown, {} collectors ran.", shown.len(), scan.header.collectors.len())?;
    if hidden > 0 {
        writeln!(w, "{hidden} entries hidden (packaged, intact) — use --all")?;
    }
    w.flush()
}

/// What the operator must know before reading the table: that the scan could
/// not see everything. Partial output that looks complete is worse than none.
fn banners(w: &mut impl Write, scan: &Scan) -> io::Result<()> {
    if !scan.header.privileged {
        writeln!(
            w,
            "! Running unprivileged. Per-user and root-owned sources were not all readable; \
             this scan is not comparable with one taken as root."
        )?;
    }
    let mut partial = Vec::new();
    let mut failed = Vec::new();
    let mut skipped = Vec::new();
    for c in &scan.header.collectors {
        match &c.status {
            Status::Partial { unreadable } => partial.push((&c.name, unreadable.len())),
            Status::Failed { error } => failed.push((&c.name, error)),
            Status::Skipped { reason } => skipped.push((&c.name, reason)),
            Status::Complete => {}
        }
    }
    for (name, error) in &failed {
        writeln!(w, "! Collector {name} failed: {error}")?;
    }
    if !partial.is_empty() {
        let list: Vec<String> = partial.iter().map(|(n, c)| format!("{n} ({c} paths)")).collect();
        writeln!(w, "! Incomplete collectors: {}. See the JSON header for the paths.", list.join(", "))?;
    }
    if !skipped.is_empty() {
        let list: Vec<String> = skipped.iter().map(|(n, r)| format!("{n} ({r})")).collect();
        writeln!(w, "  Skipped: {}", list.join(", "))?;
    }
    if !failed.is_empty() || !partial.is_empty() || !scan.header.privileged {
        writeln!(w)?;
    }
    Ok(())
}

fn flags_text(e: &Entry) -> String {
    e.flags.iter().map(|f| f.as_str()).collect::<Vec<_>>().join(",")
}

fn width_of(lens: impl Iterator<Item = usize>, min: usize, max: usize) -> usize {
    lens.max().unwrap_or(min).clamp(min, max)
}

fn clip(s: &str, w: usize) -> String {
    if s.chars().count() <= w {
        return s.to_string();
    }
    let keep = w.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('~');
    out
}

pub fn terminal_width() -> usize {
    if let Ok(cols) = std::env::var("COLUMNS") {
        if let Ok(n) = cols.parse::<usize>() {
            if n >= 40 {
                return n;
            }
        }
    }
    if io::stdout().is_terminal() {
        if let Ok(size) = rustix::termios::tcgetwinsize(io::stdout()) {
            if size.ws_col >= 40 {
                return size.ws_col as usize;
            }
        }
    }
    160
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Integrity, Provenance};
    use crate::scan::{Header, SCHEMA_VERSION};

    fn entry(name: &str, prov: Provenance, flags: &[Flag]) -> Entry {
        let mut e = Entry::new(Kind::SystemdUnit, format!("/usr/lib/systemd/system/{name}"), name);
        e.provenance = prov;
        for f in flags {
            e.flag(*f);
        }
        e
    }

    fn packaged(i: Integrity) -> Provenance {
        Provenance::Packaged { package: "openssh-server".into(), version: "9.6".into(), integrity: i }
    }

    fn scan_of(entries: Vec<Entry>) -> Scan {
        Scan {
            header: Header {
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
                enablement: crate::scan::inferred(),
                collectors: Vec::new(),
            },
            entries,
        }
    }

    #[test]
    fn a_modified_package_file_is_never_suppressed() {
        assert!(suppressed(&entry("ssh.service", packaged(Integrity::Intact), &[])));
        assert!(!suppressed(&entry("ssh.service", packaged(Integrity::Modified), &[Flag::PackagedModified])));
        assert!(!suppressed(&entry("ssh.service", packaged(Integrity::Unknown), &[])));
        assert!(!suppressed(&entry("evil.service", Provenance::Unpackaged, &[Flag::Unpackaged])));
        assert!(!suppressed(&entry("ssh.service", packaged(Integrity::Intact), &[Flag::WorldWritable])));
    }

    #[test]
    fn a_vendor_scriptlet_is_quiet_but_one_carrying_a_finding_is_not() {
        let mut shipped = Entry::new(Kind::PkgHook, "/usr/lib/sysimage/rpm/rpmdb.sqlite", "systemd:%post");
        shipped.provenance = Provenance::Packaged {
            package: "systemd".into(),
            version: "259-1".into(),
            integrity: Integrity::Unknown,
        };
        shipped.note("read_from", "rpmdb");
        assert!(suppressed(&shipped), "a few hundred vendor scriptlets are not the finding");

        let mut payload = shipped.clone();
        payload.flag(Flag::EncodingAnomaly);
        assert!(!suppressed(&payload), "a scriptlet carrying a finding must still be shown");

        // The rule is narrow: an ordinary file whose integrity is unknown is
        // still never hidden.
        let mut on_disk = shipped.clone();
        on_disk.raw.remove("read_from");
        assert!(!suppressed(&on_disk));
    }

    #[test]
    fn json_output_is_never_suppressed_and_the_table_says_what_it_hid() {
        let scan = scan_of(vec![
            entry("a.service", packaged(Integrity::Intact), &[]),
            entry("b.service", Provenance::Unpackaged, &[Flag::Unpackaged]),
        ]);

        let mut out = Vec::new();
        ndjson(&mut out, &scan, &Filters::default()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 3, "header plus both entries");

        let mut out = Vec::new();
        table(&mut out, &scan, &Filters::default(), &TableOpts { all: false, width: 120 }).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("b.service"));
        assert!(!text.contains("a.service"));
        assert!(text.contains("1 entries hidden (packaged, intact) — use --all"));
    }

    #[test]
    fn filters_compose_as_or_within_a_field_and_and_across_fields() {
        let mut a = entry("a.service", Provenance::Unpackaged, &[Flag::Unpackaged]);
        a.trigger = Trigger::Boot;
        let mut b = entry("b.service", Provenance::Unpackaged, &[Flag::WorldWritable]);
        b.trigger = Trigger::Login;

        let f = Filters { flags: vec![Flag::Unpackaged, Flag::WorldWritable], ..Default::default() };
        assert!(f.keep(&a) && f.keep(&b));

        let f = Filters {
            flags: vec![Flag::Unpackaged],
            triggers: vec![Trigger::Login],
            ..Default::default()
        };
        assert!(!f.keep(&a) && !f.keep(&b));
    }

    #[test]
    fn an_unreadable_collector_is_announced_before_the_table() {
        let mut scan = scan_of(vec![entry("a.service", Provenance::Unpackaged, &[Flag::Unpackaged])]);
        scan.header.privileged = false;
        scan.header.collectors.push(crate::scan::CollectorStatus {
            name: "cron".into(),
            entries: 0,
            status: Status::Partial { unreadable: vec!["/var/spool/cron/crontabs: EACCES".into()] },
            truncated: Vec::new(),
        });
        let mut out = Vec::new();
        table(&mut out, &scan, &Filters::default(), &TableOpts { all: false, width: 120 }).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Running unprivileged"));
        assert!(text.contains("Incomplete collectors: cron (1 paths)"));
    }
}

/// A diff is rendered like a scan with one more column. Unchanged rows are
/// the noise here, so they are what `--all` reveals.
pub fn diff_table(
    w: &mut impl Write,
    scan: &Scan,
    diffs: &[crate::diff::Diffed],
    filters: &Filters,
    opts: &TableOpts,
) -> io::Result<()> {
    banners(w, scan)?;

    let mut shown: Vec<&crate::diff::Diffed> = Vec::new();
    let mut unchanged = 0usize;
    for d in diffs.iter().filter(|d| filters.keep(&d.entry)) {
        if !opts.all && d.delta == crate::diff::Delta::Unchanged {
            unchanged += 1;
        } else {
            shown.push(d);
        }
    }

    let kind_w = width_of(shown.iter().map(|d| d.entry.kind.as_str().len()), 12, 20);
    let name_w = width_of(shown.iter().map(|d| d.entry.name.chars().count()), 12, 34);
    let fixed = 9 + 2 + 12 + 2 + kind_w + 2 + name_w + 2;
    let detail_w = opts.width.saturating_sub(fixed).max(16);

    writeln!(w, "{:<9}  {:<12}  {:<kind_w$}  {:<name_w$}  {}", "DELTA", "ID", "KIND", "NAME", "DETAIL")?;
    for d in &shown {
        let detail = match &d.delta {
            crate::diff::Delta::Changed { fields } => fields.join(", "),
            _ => match &d.entry.command {
                Some(c) => String::from_utf8_lossy(c).replace(['\n', '\t', '\r'], " "),
                None => d.entry.source.to_string_lossy().into_owned(),
            },
        };
        writeln!(
            w,
            "{:<9}  {:<12}  {:<kind_w$}  {:<name_w$}  {}",
            d.delta.label(),
            d.entry.short_id(),
            clip(d.entry.kind.as_str(), kind_w),
            clip(&d.entry.name, name_w),
            clip(&detail, detail_w),
        )?;
    }

    writeln!(w)?;
    writeln!(w, "{} entries differ.", shown.len())?;
    if unchanged > 0 {
        writeln!(w, "{unchanged} entries unchanged — use --all")?;
    }
    w.flush()
}

pub fn diff_ndjson(
    w: &mut impl Write,
    scan: &Scan,
    diffs: &[crate::diff::Diffed],
    filters: &Filters,
) -> io::Result<()> {
    serde_json::to_writer(&mut *w, &scan.header)?;
    w.write_all(b"\n")?;
    for d in diffs.iter().filter(|d| filters.keep(&d.entry)) {
        serde_json::to_writer(&mut *w, &crate::diff::to_json(d))?;
        w.write_all(b"\n")?;
    }
    w.flush()
}
