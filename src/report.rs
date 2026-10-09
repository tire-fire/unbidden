//! A scan as one HTML file: the entries as data, and a page that filters them
//! in the browser with the same query language the terminal UI uses.
//!
//! The file is self-contained (no network, no external script) and the page
//! writes every string from the scan with `textContent`, never as markup.
//! The data sits in a `<script type="application/json">` block with `<`, `>`,
//! `&` and the line separators escaped, so nothing in a file name or a
//! command line can close the block or start a tag.

use std::io::{self, Write};

use serde_json::{Map, Value, json};

use crate::entry::{Entry, Provenance};
use crate::query::provenance_words;
use crate::render::suppressed;
use crate::scan::{Scan, Status};

const TEMPLATE: &str = include_str!("report/report.html");
const CSS: &str = include_str!("report/report.css");
const QUERY_JS: &str = include_str!("report/query.js");
const APP_JS: &str = include_str!("report/app.js");

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// One entry in the shape the page (and `tests/vectors/query.json`) uses.
pub fn row(e: &Entry) -> Value {
    let (pkg, version) = match &e.provenance {
        Provenance::Packaged { package, version, .. } => (package.as_str(), version.as_str()),
        _ => ("", ""),
    };
    let notes: Map<String, Value> = e.raw.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
    json!({
        "id": e.id,
        "kind": e.kind.as_str(),
        "name": e.name,
        "source": e.source.to_string_lossy(),
        "command": e.command.as_deref().map(lossy),
        "target": e.target_path.as_ref().map(|p| p.to_string_lossy().into_owned()),
        "enabled": e.enabled.as_str(),
        "trigger": e.trigger.as_str(),
        "user": e.principal,
        "pkg": pkg,
        "version": version,
        "prov": provenance_words(&e.provenance),
        "flags": e.flags.iter().map(|f| f.as_str()).collect::<Vec<_>>(),
        "notes": notes,
        "collector": e.collector,
        "owner": e.owner_uid,
        "mode": format!("{:04o}", e.mode & 0o7777),
        "mtime": e.mtime.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()),
        "hidden": suppressed(e),
    })
}

/// What the table prints above its rows, as sentences for the page.
fn notices(scan: &Scan) -> Vec<String> {
    let mut out = Vec::new();
    if !scan.header.privileged {
        out.push("Running unprivileged. Per-user and root-owned sources were not all readable; this scan is not comparable with one taken as root.".to_string());
    }
    let mut partial = Vec::new();
    for c in &scan.header.collectors {
        match &c.status {
            Status::Partial { unreadable } => partial.push(format!("{} ({} paths)", c.name, unreadable.len())),
            Status::Failed { error } => out.push(format!("Collector {} failed: {error}", c.name)),
            Status::Skipped { reason } => out.push(format!("Skipped: {} ({reason})", c.name)),
            Status::Complete => {}
        }
    }
    if !partial.is_empty() {
        out.push(format!("Incomplete collectors: {}.", partial.join(", ")));
    }
    for f in &scan.header.enrichment_failures {
        out.push(format!("Enrichment failed, flags may be missing: {f}"));
    }
    if scan.header.package_databases.as_ref().is_some_and(Vec::is_empty) {
        out.push("No package database the tool reads was found (dpkg, rpm, apk, pacman), so no file can be told apart as packaged or not and nothing is hidden for being packaged.".to_string());
    }
    out
}

/// JSON that is safe inside a `<script>` element.
fn embed(value: &Value) -> String {
    let text = value.to_string();
    let mut out = String::with_capacity(text.len() + text.len() / 16);
    for c in text.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

pub fn write(w: &mut impl Write, scan: &Scan) -> io::Result<()> {
    let h = &scan.header;
    let data = json!({
        "header": {
            "hostname": h.hostname,
            "distro": format!("{} {}", h.distro_id, h.distro_version).trim().to_string(),
            "version": h.unbidden_version,
            "scan_time": h.scan_time,
            "privileged": h.privileged,
            "notices": notices(scan),
        },
        "entries": scan.entries.iter().map(row).collect::<Vec<_>>(),
    });
    // Filled in one pass, so text in the data that looks like a placeholder
    // is never substituted into.
    let mut page = String::with_capacity(TEMPLATE.len() + QUERY_JS.len() + APP_JS.len() + CSS.len());
    let data = embed(&data);
    let mut rest = TEMPLATE;
    while let Some(at) = rest.find("/*") {
        page.push_str(&rest[..at]);
        let tail = &rest[at..];
        let (marker, text) = if tail.starts_with("/*CSS*/") {
            ("/*CSS*/", CSS)
        } else if tail.starts_with("/*DATA*/") {
            ("/*DATA*/", data.as_str())
        } else if tail.starts_with("/*QUERY*/") {
            ("/*QUERY*/", QUERY_JS)
        } else if tail.starts_with("/*APP*/") {
            ("/*APP*/", APP_JS)
        } else {
            ("/*", "/*")
        };
        page.push_str(text);
        rest = &tail[marker.len()..];
    }
    page.push_str(rest);
    w.write_all(page.as_bytes())?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Flag, Kind};
    use crate::root::Root;

    fn scan_with(entries: Vec<Entry>) -> Scan {
        let mut s = crate::scan::run(&Root::at(std::env::temp_dir()).unwrap(), &crate::scan::Options { deep: false }, &[]);
        s.entries = entries;
        s
    }

    #[test]
    fn nothing_in_the_data_can_close_the_script_or_start_a_tag() {
        let mut e = Entry::new(Kind::Cron, "/etc/crontab", "</script><img src=x onerror=alert(1)>&\u{2028}");
        e.command = Some(b"</SCRIPT><script>alert(2)</script>".to_vec());
        e.flag(Flag::Unpackaged);
        let mut out = Vec::new();
        write(&mut out, &scan_with(vec![e])).unwrap();
        let page = String::from_utf8(out).unwrap();
        let data_start = page.find("id=\"data\">").unwrap() + 10;
        let data_end = page[data_start..].find("</script>").unwrap() + data_start;
        let data = &page[data_start..data_end];
        assert!(!data.contains('<') && !data.contains('>') && !data.contains('&'), "{data}");
        let parsed: Value = serde_json::from_str(data).unwrap();
        assert_eq!(parsed["entries"][0]["name"], "</script><img src=x onerror=alert(1)>&\u{2028}", "the data round-trips exactly");
    }

    #[test]
    fn the_page_is_one_file_with_no_outside_references() {
        let mut out = Vec::new();
        write(&mut out, &scan_with(vec![Entry::new(Kind::Cron, "/etc/crontab", "job")])).unwrap();
        let page = String::from_utf8(out).unwrap();
        for placeholder in ["/*CSS*/", "/*DATA*/", "/*QUERY*/", "/*APP*/"] {
            assert!(!page.contains(placeholder), "{placeholder} left in the page");
        }
        for outside in ["src=\"http", "href=\"http", "@import", "fetch(", "XMLHttpRequest", "innerHTML"] {
            assert!(!page.contains(outside), "{outside}");
        }
    }

    #[test]
    fn a_row_carries_what_the_query_reads() {
        let mut e = Entry::new(Kind::Cron, "/etc/crontab", "job");
        e.provenance = Provenance::Packaged { package: "cronie".into(), version: "1.7".into(), integrity: crate::entry::Integrity::Intact };
        e.note("env.LD_PRELOAD", "/tmp/x.so");
        let r = row(&e);
        assert_eq!(r["pkg"], "cronie");
        assert_eq!(r["prov"], json!(["packaged", "intact"]));
        assert_eq!(r["notes"]["env.LD_PRELOAD"], "/tmp/x.so");
        assert_eq!(r["hidden"], true, "a packaged, intact entry is hidden by default");
    }
}
