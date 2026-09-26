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
///
/// "Intact" covers what the entry runs as well as the file it was read from.
/// A packaged unit whose ExecStart= names a file with no digest to check it
/// against is §7's missing-md5sums case, one step removed, and is shown.
pub fn suppressed(e: &Entry) -> bool {
    let quiet = e.flags.iter().all(|f| *f == Flag::DegradedEnablement);
    let target_verified = e
        .raw
        .get("target_provenance")
        .is_none_or(|v| v.ends_with("(intact)") || v.ends_with("(directory)"));
    // nsswitch.conf is written at install time on every supported
    // distribution, by libc-bin's postinst from a template and edited by
    // libnss-systemd's, or rendered by authselect, and no package database
    // records what it should hold, so the file is never packaged and intact:
    // at best it is GeneratedBy libc-bin, a copy of its template. A module is
    // judged by the library glibc loads for it instead: hidden when that is
    // packaged and intact, or when there is none and glibc skips the name,
    // and never when it follows a `#` a person reads as a comment. An
    // unpackaged or modified library shows through target_provenance.
    if e.kind == Kind::NssModule && !e.provenance.is_verified() {
        let source_only = e.flags.iter().all(|f| matches!(f, Flag::DegradedEnablement | Flag::Unpackaged));
        return source_only && target_verified && !e.raw.contains_key("after_hash");
    }
    // A file whose inode changed after its package installed it was touched
    // by something other than the package manager, however it verifies.
    let untouched = !e.raw.contains_key("changed_after_install");
    quiet && target_verified && untouched && (e.provenance.is_verified() || from_package_database(e))
}

/// An entry that is the package manager's own machinery: an rpm scriptlet or
/// file trigger read out of the header, a dpkg maintainer script. Integrity
/// comes back Unknown for both, and for the same reason — no package manager
/// records a digest of its own metadata, so no scan can ever verify one.
///
/// That is different from §7's "missing md5sums" case, which is a gap in the
/// evidence about a shipped file and must never be hidden. Here there is no
/// evidence for anyone, ever, and an ordinary Debian host carries 851 of
/// them. Reporting all of them on every run teaches an operator to skip the
/// category, which costs more than it buys.
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
///
/// The one thing that can be established about a maintainer script is when
/// it last changed, and one changed after its package was installed is shown:
/// dpkg did not write it, and that is exactly the script worth reading.
fn from_package_database(e: &Entry) -> bool {
    let metadata = e.raw.contains_key("read_from") || e.raw.contains_key("digest_unavailable");
    metadata
        && !e.raw.contains_key("changed_after_install")
        && matches!(e.provenance, crate::entry::Provenance::Packaged { .. })
}

/// Text from a hostile disk, made safe to print to a terminal.
///
/// A file name, a unit's ExecStart= or a line of a crontab can carry ESC and
/// the rest of the C0 and C1 controls. Printed raw they are instructions to
/// the operator's terminal, not text: `ESC[2K ESC[1A` erases the row above,
/// so a crafted command can overwrite the table line that reports it. Bidi
/// overrides and zero-width characters do the same job more quietly, making
/// one string read as another.
///
/// Every such character is shown as an escape rather than dropped, because
/// its presence is evidence. Tabs are kept only where the caller says a
/// multi-column layout is not at stake.
pub fn visible(s: &str, keep_tabs: bool) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(|c| unsafe_char(c, keep_tabs)) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        if !unsafe_char(c, keep_tabs) {
            out.push(c);
            continue;
        }
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x100 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
        }
    }
    std::borrow::Cow::Owned(out)
}

fn unsafe_char(c: char, keep_tabs: bool) -> bool {
    if c == '\t' {
        return !keep_tabs;
    }
    c.is_control()
        || matches!(c,
            '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}')
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
    let name_w = width_of(shown.iter().map(|e| visible(&e.name, false).chars().count()), 12, 34);
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
            Some(c) => String::from_utf8_lossy(c).into_owned(),
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
            clip(&visible(&e.name, false), name_w),
            clip(&flags_text(e), flag_w),
            clip(&visible(&command, false), cmd_w),
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
        // A panic message can quote the input that caused it.
        writeln!(w, "! Collector {name} failed: {}", visible(error, false))?;
    }
    for failure in &scan.header.enrichment_failures {
        writeln!(w, "! Enrichment failed, flags may be missing: {}", visible(failure, false))?;
    }
    if !partial.is_empty() {
        let list: Vec<String> = partial.iter().map(|(n, c)| format!("{n} ({c} paths)")).collect();
        writeln!(w, "! Incomplete collectors: {}. See the JSON header for the paths.", list.join(", "))?;
    }
    if !skipped.is_empty() {
        let list: Vec<String> = skipped.iter().map(|(n, r)| format!("{n} ({r})")).collect();
        writeln!(w, "  Skipped: {}", list.join(", "))?;
    }
    if !failed.is_empty()
        || !partial.is_empty()
        || !scan.header.privileged
        || !scan.header.enrichment_failures.is_empty()
    {
        writeln!(w)?;
    }
    Ok(())
}

/// Findings first, caveats last. The column is narrow, so whatever is least
/// important has to be the part that gets clipped — and `degraded-enablement`
/// is a note about how an answer was reached, not a finding about the host.
/// Leading with it once hid `packaged-modified`, which is the single
/// highest-signal thing this tool reports.
fn flags_text(e: &Entry) -> String {
    let mut flags: Vec<&str> = e.flags.iter().map(|f| f.as_str()).collect();
    flags.sort_by_key(|f| *f == Flag::DegradedEnablement.as_str());
    flags.join(",")
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
                distro_like: String::new(),
                root: "/".into(),
                live: true,
                deep: false,
                privileged: true,
                enablement: crate::scan::inferred(),
                collectors: Vec::new(),
                enrichment_failures: Vec::new(),
            },
            entries,
        }
    }

    #[test]
    fn an_nss_module_in_an_unverified_file_is_judged_by_its_library() {
        let nss = |prov: Provenance, flags: &[Flag], target: Option<&str>, after_hash: bool| {
            let mut e = Entry::new(Kind::NssModule, "/etc/nsswitch.conf", "x");
            e.provenance = prov;
            for f in flags {
                e.flag(*f);
            }
            if let Some(t) = target {
                e.note("target_provenance", t);
            }
            if after_hash {
                e.note("after_hash", "true");
            }
            e
        };
        // Debian: libc-bin's copy of its own template.
        let generated = Provenance::Reproduced { by: "libc-bin, identical to /usr/share/libc-bin/nsswitch.conf".into() };
        assert!(suppressed(&nss(generated, &[], None, false)));
        // Mint: the file is unowned, the library ships with systemd.
        assert!(suppressed(&nss(Provenance::Unpackaged, &[Flag::Unpackaged], Some("libnss-systemd (intact)"), false)));
        // Fedora: authselect's ghost file, which has no digest.
        assert!(suppressed(&nss(packaged(Integrity::Unknown), &[], Some("systemd-libs (intact)"), false)));
        // A name with no library behind it: glibc skips it.
        assert!(suppressed(&nss(Provenance::Unpackaged, &[Flag::Unpackaged], None, false)));
        assert!(!suppressed(&nss(Provenance::Unpackaged, &[Flag::Unpackaged], Some("unpackaged"), false)));
        assert!(!suppressed(&nss(
            Provenance::Unpackaged,
            &[Flag::PackagedModified],
            Some("libnss-systemd (modified)"),
            false
        )));
        assert!(!suppressed(&nss(Provenance::Unpackaged, &[Flag::Unpackaged], None, true)), "after a `#`");
        // Other kinds keep the ordinary rule.
        assert!(!suppressed(&entry("x.service", packaged(Integrity::Unknown), &[])));
    }

    #[test]
    fn a_modified_package_file_is_never_suppressed() {
        assert!(suppressed(&entry("ssh.service", packaged(Integrity::Intact), &[])));
        assert!(!suppressed(&entry("ssh.service", packaged(Integrity::Modified), &[Flag::PackagedModified])));
        assert!(!suppressed(&entry("ssh.service", packaged(Integrity::Unknown), &[])));
        assert!(!suppressed(&entry("evil.service", Provenance::Unpackaged, &[Flag::Unpackaged])));
        assert!(!suppressed(&entry("ssh.service", packaged(Integrity::Intact), &[Flag::WorldWritable])));

        // What the unit runs has to be verified too.
        let mut e = entry("ssh.service", packaged(Integrity::Intact), &[]);
        e.note("target_provenance", "openssh-server (intact)");
        assert!(suppressed(&e));
        e.note("target_provenance", "sudo (directory)");
        assert!(suppressed(&e), "an #includedir names a directory, which has no digest to check");
        for unverified in ["openssh-server (unknown)", "generated by snapd", "unknown"] {
            e.note("target_provenance", unverified);
            assert!(!suppressed(&e), "{unverified}");
        }
    }

    #[test]
    fn the_narrow_flag_column_clips_the_caveat_not_the_finding() {
        let mut e = entry("cron.service", packaged(Integrity::Modified), &[]);
        e.flag(Flag::DegradedEnablement);
        e.flag(Flag::PackagedModified);
        assert!(flags_text(&e).starts_with("packaged-modified"), "got {}", flags_text(&e));
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

        // A dpkg maintainer script is the same case by a different route.
        let mut maintainer = shipped.clone();
        maintainer.raw.remove("read_from");
        maintainer.note("digest_unavailable", "dpkg keeps no digest for maintainer scripts");
        assert!(suppressed(&maintainer));
        let mut edited = maintainer.clone();
        edited.note("changed_after_install", "inode changed 86400s after /var/lib/dpkg/info/cron.list was written");
        assert!(!suppressed(&edited), "a script dpkg did not write is the one worth reading");

        // The rule stays narrow: a shipped file whose md5sums line is simply
        // missing is still never hidden, which is §7's rule.
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
    fn terminal_controls_from_the_scanned_disk_are_shown_not_obeyed() {
        // ESC[2K ESC[1A erases the line above: printed raw, a crafted
        // command rewrites the table row that reports it.
        let mut e = entry("x\u{1b}]0;title\u{7}.service", Provenance::Unpackaged, &[Flag::Unpackaged]);
        e.command = Some(b"/usr/bin/true \x1b[2K\x1b[1Afake\r\n\x9b31m \xe2\x80\xae evil".to_vec());
        let scan = scan_of(vec![e]);

        for all in [false, true] {
            let mut out = Vec::new();
            table(&mut out, &scan, &Filters::default(), &TableOpts { all, width: 400 }).unwrap();
            let text = String::from_utf8(out).unwrap();
            assert!(!text.contains('\u{1b}') && !text.contains('\u{7}') && !text.contains('\u{9b}'), "{text:?}");
            assert!(!text.contains('\u{202e}'), "a bidi override reorders what the operator reads");
            assert!(text.contains("\\x1b[2K\\x1b[1Afake\\r\\n"), "{text}");
            assert!(text.contains("\\u{202e}"));
            assert!(text.contains("x\\x1b]0;title\\x07.service"));
        }

        assert_eq!(visible("plain text", false), "plain text");
        assert_eq!(visible("a\tb", true), "a\tb");
        assert_eq!(visible("a\tb", false), "a\\tb");
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

        scan.header.enrichment_failures.push("provenance: rpm database: bad header".into());
        let mut out = Vec::new();
        table(&mut out, &scan, &Filters::default(), &TableOpts { all: false, width: 120 }).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("! Enrichment failed, flags may be missing: provenance: rpm database: bad header"));
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
    let name_w = width_of(shown.iter().map(|d| visible(&d.entry.name, false).chars().count()), 12, 34);
    let fixed = 9 + 2 + 12 + 2 + kind_w + 2 + name_w + 2;
    let detail_w = opts.width.saturating_sub(fixed).max(16);

    writeln!(w, "{:<9}  {:<12}  {:<kind_w$}  {:<name_w$}  {}", "DELTA", "ID", "KIND", "NAME", "DETAIL")?;
    for d in &shown {
        let detail = match &d.delta {
            crate::diff::Delta::Changed { fields } => fields.join(", "),
            _ => match &d.entry.command {
                Some(c) => String::from_utf8_lossy(c).into_owned(),
                None => d.entry.source.to_string_lossy().into_owned(),
            },
        };
        writeln!(
            w,
            "{:<9}  {:<12}  {:<kind_w$}  {:<name_w$}  {}",
            d.delta.label(),
            d.entry.short_id(),
            clip(d.entry.kind.as_str(), kind_w),
            clip(&visible(&d.entry.name, false), name_w),
            clip(&visible(&detail, false), detail_w),
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
