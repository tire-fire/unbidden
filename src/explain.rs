//! `explain <id>` — everything known about one entry, including the text it
//! was parsed from.
//!
//! The source text is here and never in `scan`, and the distinction is
//! consent: `scan --json` output gets pasted into tickets and chat rooms,
//! while `explain <id>` is a deliberate request for one entry.
//!
//! The file is re-read rather than replayed from the scan, on purpose. On a
//! live compromised host an entry whose bytes changed between the scan and
//! the inspection is itself a finding.

use std::io::{self, Write};

use crate::entry::{Entry, Provenance};
use crate::provenance;
use crate::render::visible;
use crate::root::Root;
use crate::scan::Scan;

/// A whole file under this size is shown as-is; beyond it, only the region
/// around the entry plus context.
pub const WHOLE_FILE_LIMIT: usize = 64 * 1024;
const CONTEXT_LINES: usize = 20;

pub fn find<'a>(scan: &'a Scan, prefix: &str) -> Result<&'a Entry, String> {
    let prefix = prefix.trim().to_ascii_lowercase();
    if prefix.is_empty() {
        return Err("give an entry id, or a unique prefix of one".into());
    }
    let matches: Vec<&Entry> = scan.entries.iter().filter(|e| e.id.starts_with(&prefix)).collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(format!("no entry with id starting {prefix}")),
        n => Err(format!(
            "{n} entries start with {prefix}: {}",
            matches
                .iter()
                .take(6)
                .map(|e| format!("{} ({})", e.short_id(), visible(&e.name, false)))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub fn write(w: &mut impl Write, root: &Root, entry: &Entry, show_source: bool) -> io::Result<()> {
    // Everything below except the fixed labels came off the scanned disk.
    let t = |s: &str| visible(s, false).into_owned();
    let p = |p: &std::path::Path| t(&p.to_string_lossy());
    writeln!(w, "id          {}", entry.id)?;
    writeln!(w, "kind        {}", entry.kind)?;
    writeln!(w, "name        {}", t(&entry.name))?;
    writeln!(w, "source      {}", p(&entry.source))?;
    writeln!(w, "trigger     {}", entry.trigger)?;
    writeln!(w, "enabled     {}", entry.enabled)?;
    if let Some(who) = &entry.principal {
        writeln!(w, "runs as     {}", t(who))?;
    }
    writeln!(w, "owner uid   {}", entry.owner_uid)?;
    writeln!(w, "mode        {:04o}", entry.mode)?;
    if let Some(m) = entry.mtime {
        writeln!(w, "mtime       {} (unix)", unix(m))?;
    }
    match &entry.command {
        Some(c) => match std::str::from_utf8(c) {
            Ok(s) => writeln!(w, "command     {}", t(s))?,
            Err(_) => writeln!(w, "command     <{} bytes, not valid UTF-8> {}", c.len(), crate::entry::hex(c))?,
        },
        None => writeln!(w, "command     (none — the entry is the script)")?,
    }
    if let Some(target) = &entry.target_path {
        writeln!(w, "target      {}", p(target))?;
    }
    if let Some(h) = &entry.target_sha256 {
        writeln!(w, "sha256      {}", t(h))?;
    }
    writeln!(w, "provenance  {}", t(&describe(&entry.provenance)))?;
    if entry.flags.is_empty() {
        writeln!(w, "flags       (none)")?;
    } else {
        writeln!(w, "flags       {}", entry.flags.iter().map(|f| f.as_str()).collect::<Vec<_>>().join(", "))?;
    }
    if !entry.raw.is_empty() {
        writeln!(w)?;
        writeln!(w, "collector notes")?;
        for (k, v) in &entry.raw {
            writeln!(w, "  {} = {}", t(k), t(v))?;
        }
    }

    verify_unchanged(w, root, entry)?;

    if show_source {
        writeln!(w)?;
        write_source(w, root, entry)?;
    }
    w.flush()
}

/// Did the file move under us between the scan and this inspection?
fn verify_unchanged(w: &mut impl Write, root: &Root, entry: &Entry) -> io::Result<()> {
    let Some(recorded) = &entry.target_sha256 else { return Ok(()) };
    let hashed = entry.target_path.clone().unwrap_or_else(|| entry.source.clone());
    let rel = root.rel(&hashed);
    match provenance::digests(root, &rel) {
        Some(now) if &now.sha256 != recorded => {
            writeln!(w)?;
            writeln!(
                w,
                "!! {} changed since the scan: recorded {}, now {}",
                visible(&hashed.to_string_lossy(), false),
                visible(recorded, false),
                now.sha256
            )?;
            writeln!(w, "   On a host under investigation that is itself a finding.")?;
        }
        None if root.exists(&rel) => {
            writeln!(w)?;
            writeln!(w, "!! {} can no longer be hashed", visible(&hashed.to_string_lossy(), false))?;
        }
        None => {
            writeln!(w)?;
            writeln!(w, "!! {} has gone since the scan", visible(&hashed.to_string_lossy(), false))?;
        }
        _ => {}
    }
    Ok(())
}

fn write_source(w: &mut impl Write, root: &Root, entry: &Entry) -> io::Result<()> {
    // Some entries were read out of a binary database, not a text file.
    // Dumping twenty lines of mangled sqlite helps nobody, and the record
    // itself is already above in `command`.
    if let Some(from) = entry.raw.get("read_from") {
        writeln!(
            w,
            "source is the {} database at {}, not a text file",
            visible(from, false),
            visible(&entry.source.to_string_lossy(), false)
        )?;
        writeln!(w, "the record itself is the command shown above")?;
        return Ok(());
    }

    let rel = root.rel(&entry.source);
    let Ok((bytes, truncated)) = root.read_capped(&rel, WHOLE_FILE_LIMIT * 16) else {
        writeln!(w, "source text  (unreadable)")?;
        return Ok(());
    };

    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();

    if bytes.len() <= WHOLE_FILE_LIMIT && !truncated {
        writeln!(w, "source text of {} ({} bytes)", visible(&entry.source.to_string_lossy(), false), bytes.len())?;
        for (n, line) in lines.iter().enumerate() {
            writeln!(w, "{:>5}  {}", n + 1, visible(line, true))?;
        }
        return Ok(());
    }

    // Too large to show whole: find where this entry lives and show around it.
    let needle = entry
        .command
        .as_ref()
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .unwrap_or_else(|| entry.name.clone());
    let hit = lines.iter().position(|l| l.contains(needle.trim())).unwrap_or(0);
    let first = hit.saturating_sub(CONTEXT_LINES);
    let last = (hit + CONTEXT_LINES + 1).min(lines.len());

    writeln!(
        w,
        "source text of {} (lines {}-{} of {}{})",
        visible(&entry.source.to_string_lossy(), false),
        first + 1,
        last,
        lines.len(),
        if truncated { "+, file exceeds the read cap" } else { "" }
    )?;
    for (n, line) in lines[first..last].iter().enumerate() {
        writeln!(w, "{:>5}  {}", first + n + 1, visible(line, true))?;
    }
    Ok(())
}

fn describe(p: &Provenance) -> String {
    match p {
        Provenance::Packaged { package, version, integrity } => {
            format!("{package} {version}, contents {integrity}")
        }
        Provenance::GeneratedBy { by } => format!("generated by {by}"),
        Provenance::Unpackaged => "no package owns this file".into(),
        Provenance::Unknown => "unknown (no package database, or the file is outside it)".into(),
    }
}

fn unix(t: std::time::SystemTime) -> i64 {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Kind;
    use crate::scan::{Header, SCHEMA_VERSION};

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
                enrichment_failures: Vec::new(),
            },
            entries,
        }
    }

    #[test]
    fn a_unique_prefix_resolves_and_an_ambiguous_one_says_so() {
        let a = Entry::new(Kind::Cron, "/etc/crontab", "one");
        let b = Entry::new(Kind::Cron, "/etc/crontab", "two");
        let scan = scan_of(vec![a.clone(), b.clone()]);

        assert_eq!(find(&scan, &a.id).unwrap().name, "one");
        assert_eq!(find(&scan, a.short_id()).unwrap().name, "one");
        assert!(find(&scan, "zzzz").unwrap_err().contains("no entry"));
        assert!(find(&scan, "").unwrap_err().contains("unique prefix"));

        // Both ids start with the empty-ish prefix of their shared first
        // character often enough to matter; force the ambiguous case.
        let shared = &a.id[..1];
        if b.id.starts_with(shared) {
            assert!(find(&scan, shared).unwrap_err().contains("entries start with"));
        }
    }

    #[test]
    fn explain_reports_a_file_that_changed_since_the_scan() {
        let dir = std::env::temp_dir().join(format!("unbidden-explain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/rc.local"), b"#!/bin/sh\n/usr/local/bin/start\n").unwrap();

        let root = Root::at(&dir).unwrap();
        let mut e = Entry::new(Kind::RcLocal, root.abs("etc/rc.local"), "rc.local");
        e.target_sha256 = provenance::digests(&root, std::path::Path::new("etc/rc.local")).map(|d| d.sha256);

        let mut out = Vec::new();
        write(&mut out, &root, &e, true).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("changed since the scan"));
        assert!(text.contains("/usr/local/bin/start"), "the source text is shown");

        std::fs::write(dir.join("etc/rc.local"), b"#!/bin/sh\n/tmp/evil\n").unwrap();
        let mut out = Vec::new();
        write(&mut out, &root, &e, false).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("changed since the scan"), "{text}");
        assert!(!text.contains("/tmp/evil"), "--no-source withholds the text");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn explain_shows_control_bytes_in_the_source_as_escapes() {
        let dir = std::env::temp_dir().join(format!("unbidden-explain-esc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/rc.local"), b"#!/bin/sh\n\tindent\n/tmp/x \x1b[2K\x1b[1Aclean\n").unwrap();

        let root = Root::at(&dir).unwrap();
        let mut e = Entry::new(Kind::RcLocal, root.abs("etc/rc.local"), "rc.\u{1b}[31mlocal");
        e.command = Some(b"/tmp/x \x1b[2K".to_vec());
        e.note("line", "\u{1b}[1A");

        let mut out = Vec::new();
        write(&mut out, &root, &e, true).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(text.contains("/tmp/x \\x1b[2K\\x1b[1Aclean"));
        assert!(text.contains("name        rc.\\x1b[31mlocal"));
        assert!(text.contains("\tindent"), "a tab in a source line is layout, not an attack");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
