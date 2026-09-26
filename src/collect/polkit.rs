//! polkit: what decides whether an unprivileged user may do a privileged
//! thing — pkexec, managing systemd units, mounting disks — and the action
//! definitions that set each action's default answer. A rule granting that
//! for everyone hands out the privilege with no password.
//!
//! Two engines ship on the supported set, and each reads different files.
//! polkit 0.105 (Ubuntu 22.04, Mint 21) reads `.pkla` sections from the local
//! authority; 121 and later evaluate JavaScript from `rules.d`. Ubuntu's 0.105
//! still carries files in /usr/share/polkit-1/rules.d that it never reads, so
//! the engine is taken from the daemon itself: only the JavaScript one holds
//! `polkit._runRules`, and only 0.105 holds the local-authority backend.

use std::path::Path;

use super::replaceable;
use crate::entry::{Enablement, Entry, Flag, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Polkit;

const DAEMONS: [&str; 3] = ["usr/lib/polkit-1/polkitd", "usr/libexec/polkitd", "usr/lib/policykit-1/polkitd"];
const DAEMON_CAP: usize = 8 << 20;
const FILE_CAP: usize = 256 * 1024;

/// polkit 124 reads the first and last; 125 and later all four. A directory
/// an older daemon does not read is still walked: a file there is evidence.
const RULES_DIRS: [&str; 4] = [
    "etc/polkit-1/rules.d",
    "run/polkit-1/rules.d",
    "usr/local/share/polkit-1/rules.d",
    "usr/share/polkit-1/rules.d",
];
const ACTION_DIRS: [&str; 4] = [
    "etc/polkit-1/actions",
    "run/polkit-1/actions",
    "usr/local/share/polkit-1/actions",
    "usr/share/polkit-1/actions",
];
const PKLA_DIRS: [&str; 2] = ["etc/polkit-1/localauthority", "var/lib/polkit-1/localauthority"];
const AUTHORITY_CONF: &str = "etc/polkit-1/localauthority.conf.d";

#[derive(PartialEq)]
enum Engine {
    Js,
    LocalAuthority,
}

impl Collector for Polkit {
    fn name(&self) -> &'static str {
        "polkit"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        // No daemon, nothing evaluates any of it.
        let Some(engine) = engine(cx) else { return Vec::new() };
        let mut out = Vec::new();
        match engine {
            Engine::Js => rules(cx, &mut out),
            Engine::LocalAuthority => {
                pkla(cx, &mut out);
                admin_identities(cx, &mut out);
            }
        }
        actions(cx, &mut out);
        out
    }
}

fn engine(cx: &mut Ctx) -> Option<Engine> {
    let rel = DAEMONS.iter().find(|d| cx.root.exists(d))?;
    let bytes = cx.read_capped(rel, DAEMON_CAP)?;
    let has = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    // A daemon that says neither is taken for the current engine.
    Some(if !has(b"polkit._runRules") && has(b"polkitbackendlocalauthority") {
        Engine::LocalAuthority
    } else {
        Engine::Js
    })
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn entry(cx: &mut Ctx, kind: Kind, rel: &Path, name: String) -> Entry {
    let mut e = cx.entry(kind, rel, name);
    e.trigger = Trigger::Auth;
    e.enabled = Enablement::Enabled;
    e
}

// ---------------------------------------------------------------- rules ----

/// One entry per rules file, in the order polkitd loads them: by file name
/// across the directories, a same-named file in an earlier directory
/// replacing the later one. The JavaScript is not run. What is read from it
/// literally: whether it can answer YES, the user and group names it tests,
/// and the argv of a `polkit.spawn` given as literals, whose program becomes
/// the target.
fn rules(cx: &mut Ctx, out: &mut Vec<Entry>) {
    for (rel, shadowed_by) in replaceable(cx, &RULES_DIRS, ".rules") {
        let Some(bytes) = cx.read_capped(&rel, FILE_CAP) else { continue };
        let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut e = entry(cx, Kind::PolkitRule, &rel, name);
        if let Some(by) = &shadowed_by {
            e.enabled = Enablement::Disabled;
            e.note("shadowed_by", cx.root.abs(by).display().to_string());
        }
        if contains(&bytes, b"polkit.Result.YES") {
            e.note("returns_yes", "true");
        }
        let groups = literals_after(&bytes, &[b"isInGroup("]);
        let users = literals_after(&bytes, &[b".user ==", b".user==", b".user ===", b".user==="]);
        if !groups.is_empty() {
            e.note("groups", groups.join(", "));
        }
        if !users.is_empty() {
            e.note("users", users.join(", "));
        }
        if let Some(argv) = spawn_argv(&bytes) {
            e.target_path = argv.first().filter(|p| p.starts_with('/')).map(Into::into);
            e.command = Some(argv.join(" ").into_bytes());
        }
        if std::str::from_utf8(&bytes).is_err() {
            e.flag(Flag::EncodingAnomaly);
        }
        out.push(e);
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A JavaScript string literal at the start of `s`, after any whitespace:
/// its text and what follows the closing quote. Escapes are kept as written.
fn literal(s: &[u8]) -> Option<(String, &[u8])> {
    let s = s.trim_ascii_start();
    let quote = *s.first().filter(|q| matches!(q, b'"' | b'\''))?;
    let mut i = 1;
    while i < s.len() && s[i] != quote {
        i += if s[i] == b'\\' { 2 } else { 1 };
    }
    let body = s.get(1..i)?;
    Some((lossy(body), s.get(i + 1..).unwrap_or_default()))
}

/// Every string literal that directly follows one of `needles`.
fn literals_after(bytes: &[u8], needles: &[&[u8]]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for needle in needles {
        let mut rest = bytes;
        while let Some(at) = rest.windows(needle.len()).position(|w| w == *needle) {
            rest = &rest[at + needle.len()..];
            if let Some((text, _)) = literal(rest) {
                if !out.contains(&text) {
                    out.push(text);
                }
            }
        }
    }
    out
}

/// The argv of the first `polkit.spawn([...])`, as far as it is literals.
fn spawn_argv(bytes: &[u8]) -> Option<Vec<String>> {
    let needle = b"polkit.spawn(";
    let at = bytes.windows(needle.len()).position(|w| w == needle)?;
    let mut rest = bytes[at + needle.len()..].trim_ascii_start().strip_prefix(b"[")?;
    let mut argv = Vec::new();
    while let Some((word, after)) = literal(rest) {
        argv.push(word);
        let after = after.trim_ascii_start();
        match after.strip_prefix(b",") {
            Some(next) => rest = next,
            None => break,
        }
    }
    (!argv.is_empty()).then_some(argv)
}

// ----------------------------------------------------------------- pkla ----

/// polkit 0.105's local authority: every `.pkla` file one level down in
/// either directory, one entry per section. INI: `[section]`, then
/// Identity, Action and the three Result keys.
fn pkla(cx: &mut Ctx, out: &mut Vec<Entry>) {
    for top in PKLA_DIRS {
        let mut subdirs: Vec<_> = cx.dir(top).into_iter().filter(|d| d.is_dir).map(|d| d.name).collect();
        subdirs.sort();
        for sub in subdirs {
            let dir = Path::new(top).join(&sub);
            let mut files: Vec<_> = cx
                .dir(&dir)
                .into_iter()
                .filter(|f| !f.is_dir && f.name.as_encoded_bytes().ends_with(b".pkla"))
                .map(|f| f.name)
                .collect();
            files.sort();
            for f in files {
                let rel = dir.join(&f);
                let Some(bytes) = cx.read_capped(&rel, FILE_CAP) else { continue };
                for (section, keys) in ini(&bytes) {
                    let mut e = entry(cx, Kind::PolkitRule, &rel, section);
                    let get = |k: &str| keys.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
                    let identity = get("Identity").unwrap_or_default();
                    // A section for exactly one user names whom it serves.
                    let ids: Vec<&str> = identity.split(';').filter(|s| !s.is_empty()).collect();
                    if let [one] = ids[..] {
                        e.principal = one.strip_prefix("unix-user:").map(str::to_string);
                    }
                    e.note("identity", identity.clone());
                    for key in ["Action", "ResultAny", "ResultInactive", "ResultActive"] {
                        if let Some(v) = get(key) {
                            if v == "yes" {
                                e.note("returns_yes", "true");
                            }
                            e.note(&key.to_ascii_lowercase(), v);
                        }
                    }
                    if std::str::from_utf8(&bytes).is_err() {
                        e.flag(Flag::EncodingAnomaly);
                    }
                    out.push(e);
                }
            }
        }
    }
}

/// `[section]` headers and the `key=value` lines under each. `#` and `;`
/// start comments; lines before the first section belong to none and are
/// dropped.
fn ini(bytes: &[u8]) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for raw in bytes.split(|b| *b == b'\n') {
        let line = raw.trim_ascii();
        if line.is_empty() || line[0] == b'#' || line[0] == b';' {
            continue;
        }
        if line[0] == b'[' && line.ends_with(b"]") {
            out.push((lossy(&line[1..line.len() - 1]), Vec::new()));
        } else if let (Some((_, keys)), Some(eq)) = (out.last_mut(), line.iter().position(|b| *b == b'=')) {
            keys.push((lossy(line[..eq].trim_ascii()), lossy(line[eq + 1..].trim_ascii())));
        }
    }
    out
}

/// localauthority.conf.d's AdminIdentities: whose password answers an
/// auth_admin challenge. Adding an account there makes its own password an
/// administrator's.
fn admin_identities(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let mut files: Vec<_> = cx
        .dir(AUTHORITY_CONF)
        .into_iter()
        .filter(|f| !f.is_dir && f.name.as_encoded_bytes().ends_with(b".conf"))
        .map(|f| f.name)
        .collect();
    files.sort();
    for f in files {
        let rel = Path::new(AUTHORITY_CONF).join(&f);
        let Some(bytes) = cx.read_capped(&rel, FILE_CAP) else { continue };
        for (_, keys) in ini(&bytes) {
            for (key, value) in keys {
                if key == "AdminIdentities" {
                    let mut e = entry(cx, Kind::PolkitRule, &rel, "AdminIdentities".into());
                    e.note("identity", value);
                    out.push(e);
                }
            }
        }
    }
}

// -------------------------------------------------------------- actions ----

/// One entry per action definition file. An unpackaged or modified one is the
/// finding; what is read out of it are the actions that need no
/// authentication and the programs an exec.path annotation lets pkexec run
/// under an action's defaults.
fn actions(cx: &mut Ctx, out: &mut Vec<Entry>) {
    for (rel, shadowed_by) in replaceable(cx, &ACTION_DIRS, ".policy") {
        let Some(bytes) = cx.read_capped(&rel, FILE_CAP) else { continue };
        let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut e = entry(cx, Kind::PolkitAction, &rel, name);
        if let Some(by) = &shadowed_by {
            e.enabled = Enablement::Disabled;
            e.note("shadowed_by", cx.root.abs(by).display().to_string());
        }
        let (mut no_auth, mut exec) = (Vec::new(), Vec::new());
        for action in elements(&bytes, b"<action", b"</action>") {
            let id = attr(action, b"id=").unwrap_or_default();
            let yes: Vec<&str> = ["allow_any", "allow_inactive", "allow_active"]
                .into_iter()
                .filter(|k| text_of(action, k.as_bytes()).is_some_and(|v| v == "yes"))
                .collect();
            if !yes.is_empty() {
                no_auth.push(format!("{id} ({})", yes.join(", ")));
            }
            for a in elements(action, b"<annotate", b"</annotate>") {
                if attr(a, b"key=").as_deref() == Some("org.freedesktop.policykit.exec.path") {
                    if let Some(gt) = a.iter().position(|b| *b == b'>') {
                        let path = lossy(a[gt + 1..].split(|b| *b == b'<').next().unwrap_or_default().trim_ascii());
                        exec.push(format!("{id}: {path}"));
                    }
                }
            }
        }
        if !no_auth.is_empty() {
            e.note("no_auth_actions", no_auth.join("; "));
        }
        if !exec.is_empty() {
            e.note("exec_paths", exec.join("; "));
        }
        out.push(e);
    }
}

/// Each span from `open` to the next `close`, or to the end if unclosed.
fn elements<'a>(bytes: &'a [u8], open: &[u8], close: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while let Some(at) = rest.windows(open.len()).position(|w| w == open) {
        let span = &rest[at..];
        let end = span.windows(close.len()).position(|w| w == close).map_or(span.len(), |e| e + close.len());
        out.push(&span[..end]);
        rest = &span[end..];
    }
    out
}

/// The value of the first `name` attribute in an element's opening tag.
fn attr(element: &[u8], name: &[u8]) -> Option<String> {
    let tag = &element[..element.iter().position(|b| *b == b'>').unwrap_or(element.len())];
    let at = tag.windows(name.len()).position(|w| w == name)?;
    literal(&tag[at + name.len()..]).map(|(v, _)| v)
}

/// The text of the first `<tag>...</tag>` inside an element.
fn text_of(element: &[u8], tag: &[u8]) -> Option<String> {
    let open = [b"<", tag, b">"].concat();
    let at = element.windows(open.len()).position(|w| w == open.as_slice())? + open.len();
    let text = element[at..].split(|b| *b == b'<').next()?;
    Some(lossy(text.trim_ascii()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan, Status};
    use std::path::PathBuf;

    fn tree(tag: &str, daemon: &[u8]) -> PathBuf {
        let d = std::env::temp_dir().join(format!("unbidden-polkit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/lib/polkit-1/polkitd", daemon);
        put(&d, "etc/passwd", b"root:x:0:0::/root:/bin/sh\n");
        d
    }

    fn put(dir: &Path, rel: &str, body: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        crate::scan::run(&root, &Options { deep: false }, &[Box::new(Polkit)])
    }

    fn one<'a>(s: &'a Scan, name: &str) -> &'a Entry {
        let found: Vec<_> = s.entries.iter().filter(|e| e.name == name).collect();
        assert_eq!(found.len(), 1, "{name}: {:?}", s.entries.iter().map(|e| &e.name).collect::<Vec<_>>());
        found[0]
    }

    const JS: &[u8] = b"\x7fELF...polkit._runRules = function(action, subject) {...";
    const PKLA: &[u8] = b"\x7fELF...polkitbackendlocalauthority.c...";

    #[test]
    fn javascript_rules_are_read_in_load_order_and_their_literals_noted() {
        let d = tree("js", JS);
        put(
            &d,
            "etc/polkit-1/rules.d/49-evil.rules",
            br#"polkit.addRule(function(action, subject) {
                if (subject.isInGroup("staff") || subject.user == 'mallory') {
                    polkit.spawn(["/opt/hook", "--from", action.id]);
                    return polkit.Result.YES;
                }
            });"#,
        );
        put(&d, "etc/polkit-1/rules.d/50-default.rules", b"// admin copy\n");
        put(&d, "usr/share/polkit-1/rules.d/50-default.rules", b"polkit.addAdminRule(function(){return [\"unix-group:sudo\"];});\n");
        put(&d, "usr/share/polkit-1/rules.d/README", b"not a rule\n");
        let s = scan(&d);
        assert_eq!(s.entries.iter().filter(|e| e.kind == Kind::PolkitRule).count(), 3);

        let evil = one(&s, "49-evil.rules");
        assert_eq!((evil.trigger, evil.enabled), (Trigger::Auth, Enablement::Enabled));
        assert_eq!(evil.raw["returns_yes"], "true");
        assert_eq!(evil.raw["groups"], "staff");
        assert_eq!(evil.raw["users"], "mallory");
        assert_eq!(evil.target_path, Some(PathBuf::from("/opt/hook")), "the literal part of the spawn argv");
        assert_eq!(evil.command.as_deref(), Some(b"/opt/hook --from".as_slice()));

        let vendor = s.entries.iter().find(|e| e.source.starts_with(d.join("usr"))).unwrap();
        assert_eq!(vendor.enabled, Enablement::Disabled, "/etc replaces the same name in /usr/share");
        assert!(vendor.raw["shadowed_by"].ends_with("etc/polkit-1/rules.d/50-default.rules"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn polkit_0_105_reads_pkla_sections_and_ignores_rules_d() {
        let d = tree("pkla", PKLA);
        put(&d, "usr/share/polkit-1/rules.d/50-default.rules", b"polkit.addRule(function(){});\n");
        put(
            &d,
            "etc/polkit-1/localauthority/50-local.d/evil.pkla",
            b"# no password for mallory\n[Allow mallory]\nIdentity=unix-user:mallory\nAction=*\nResultAny=yes\nResultInactive=yes\nResultActive=yes\n\n\
              [Staff mounts]\nIdentity=unix-group:staff;unix-user:bob\nAction=org.freedesktop.udisks2.*\nResultActive=auth_self\n",
        );
        put(&d, "etc/polkit-1/localauthority.conf.d/51-admin.conf", b"[Configuration]\nAdminIdentities=unix-group:sudo;unix-user:mallory\n");
        let s = scan(&d);
        assert!(s.entries.iter().all(|e| !e.name.ends_with(".rules")), "0.105 never reads rules.d");

        let allow = one(&s, "Allow mallory");
        assert_eq!(allow.principal.as_deref(), Some("mallory"));
        assert_eq!(allow.raw["returns_yes"], "true");
        assert_eq!(allow.raw["action"], "*");
        let staff = one(&s, "Staff mounts");
        assert_eq!(staff.principal, None, "two identities name no single account");
        assert!(!staff.raw.contains_key("returns_yes"));
        assert_eq!(one(&s, "AdminIdentities").raw["identity"], "unix-group:sudo;unix-user:mallory");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn an_action_file_notes_what_needs_no_password_and_what_pkexec_may_run() {
        let d = tree("actions", JS);
        put(
            &d,
            "usr/share/polkit-1/actions/org.evil.policy",
            br#"<?xml version="1.0"?><policyconfig>
              <action id="org.evil.run">
                <defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>yes</allow_active></defaults>
                <annotate key="org.freedesktop.policykit.exec.path">/opt/evil</annotate>
              </action>
              <action id='org.evil.ask'><defaults><allow_active>auth_admin</allow_active></defaults></action>
              <action id="org.evil.unclosed"><defaults><allow_any>yes"#,
        );
        let s = scan(&d);
        let file = one(&s, "org.evil.policy");
        assert_eq!(file.kind, Kind::PolkitAction);
        assert_eq!(file.raw["no_auth_actions"], "org.evil.run (allow_active); org.evil.unclosed (allow_any)");
        assert_eq!(file.raw["exec_paths"], "org.evil.run: /opt/evil");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn no_daemon_means_nothing_is_evaluated() {
        let d = std::env::temp_dir().join(format!("unbidden-polkit-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "etc/polkit-1/rules.d/49-evil.rules", b"return polkit.Result.YES;");
        let s = scan(&d);
        assert!(s.entries.is_empty());
        assert_eq!(s.header.collectors[0].status, Status::Complete);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
