//! Network super-servers: xinetd and inetd listen on a port and start a
//! program, often as root, for each connection. The listener itself is a
//! systemd unit and is reported as one; the programs it starts are named only
//! in these files.
//!
//! Both are read only where their daemon is installed. A configuration left
//! behind by a removed package starts nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Flag, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Inetd;

const XINETD: &str = "usr/sbin/xinetd";
const XINETD_CONF: &str = "etc/xinetd.conf";
/// openbsd-inetd and inetutils-inetd, which both read /etc/inetd.conf.
const INETD: [&str; 2] = ["usr/sbin/inetd", "usr/sbin/inetutils-inetd"];
const INETD_CONF: &str = "etc/inetd.conf";
const FILE_CAP: usize = 256 * 1024;
/// includedir and include nest; a loop ends here rather than in the stack.
const MAX_DEPTH: usize = 8;

impl Collector for Inetd {
    fn name(&self) -> &'static str {
        "inetd"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        if cx.root.exists(XINETD) {
            xinetd(cx, &mut out);
        }
        if INETD.iter().any(|d| cx.root.exists(d)) {
            inetd(cx, &mut out);
        }
        out
    }
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Names are hashed into the entry id, so a second service of the same name
/// in one file needs a name of its own.
fn uniq(used: &mut BTreeMap<(PathBuf, String), usize>, rel: &Path, base: String) -> String {
    let seen = used.entry((rel.to_path_buf(), base.clone())).or_insert(0);
    *seen += 1;
    if *seen == 1 { base } else { format!("{base}#{seen}") }
}

// --------------------------------------------------------------- xinetd ----

/// One `service NAME { ... }` block: where it came from and its attributes,
/// each the value its last `=` gave it.
struct Service {
    rel: PathBuf,
    name: String,
    attrs: BTreeMap<String, String>,
}

#[derive(Default)]
struct Xinetd {
    services: Vec<Service>,
    /// `defaults { enabled = ... }`: when given, only the ids it names run.
    enabled: Option<Vec<String>>,
    /// `defaults { disabled = ... }`: ids that do not run.
    disabled: Vec<String>,
}

/// xinetd.conf as xinetd 2.3.15 reads it (parse.c, includedir.c): `defaults`
/// and `service NAME` blocks of `attribute op value...` lines, `#` comments,
/// and `include FILE` and `includedir DIR` at the top level. An included
/// directory is read in strcmp order, skipping any name that contains a `.`
/// or ends in `~`, so `telnet.bak` and `telnet~` never load. `+=` and `-=`
/// apply only to list attributes; on any other, xinetd rejects the line.
fn xinetd(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let mut conf = Xinetd::default();
    xinetd_file(cx, Path::new(XINETD_CONF), 0, &mut conf);

    let mut used = BTreeMap::new();
    for s in conf.services {
        let id = s.attrs.get("id").cloned().unwrap_or_else(|| s.name.clone());
        let base = if id == s.name { s.name.clone() } else { format!("{} ({id})", s.name) };
        let name = uniq(&mut used, &s.rel, base);
        let mut e = cx.entry(Kind::InetdService, &s.rel, name);
        e.trigger = Trigger::NetworkEvent;
        e.note("daemon", "xinetd");
        let switched_off = s.attrs.get("disable").is_some_and(|v| v.eq_ignore_ascii_case("yes"))
            || conf.disabled.contains(&id)
            || conf.enabled.as_ref().is_some_and(|only| !only.contains(&id));
        e.enabled = if switched_off { Enablement::Disabled } else { Enablement::Enabled };
        e.principal = s.attrs.get("user").cloned();
        for key in ["id", "port", "socket_type", "protocol", "type", "redirect", "server_args"] {
            if let Some(v) = s.attrs.get(key) {
                e.note(key, v.clone());
            }
        }
        // An INTERNAL service is xinetd's own code, and a redirect forwards
        // the connection elsewhere; neither starts a program.
        let internal = s.attrs.get("type").is_some_and(|t| t.split_whitespace().any(|w| w == "INTERNAL"));
        if let (false, Some(server)) = (internal, s.attrs.get("server")) {
            let args = s.attrs.get("server_args").map(|a| format!(" {a}")).unwrap_or_default();
            e.command = Some(format!("{server}{args}").into_bytes());
            e.target_path = Some(PathBuf::from(server));
        }
        out.push(e);
    }
}

fn xinetd_file(cx: &mut Ctx, rel: &Path, depth: usize, conf: &mut Xinetd) {
    if depth > MAX_DEPTH {
        return;
    }
    let Some(bytes) = cx.read_capped(rel, FILE_CAP) else { return };
    let mut block: Option<(Option<String>, BTreeMap<String, String>)> = None;
    for raw in bytes.split(|b| *b == b'\n') {
        let line = raw.split(|b| *b == b'#').next().unwrap_or_default().trim_ascii();
        if line.is_empty() {
            continue;
        }
        let words: Vec<&[u8]> = line.split(u8::is_ascii_whitespace).filter(|w| !w.is_empty()).collect();
        match (&mut block, words.as_slice()) {
            (None, [b"service", name] | [b"service", name, b"{"]) => block = Some((Some(lossy(name)), BTreeMap::new())),
            (None, [b"defaults"] | [b"defaults", b"{"]) => block = Some((None, BTreeMap::new())),
            (None, [b"includedir", dir]) => {
                let dir = include_path(dir);
                let mut names: Vec<_> = cx
                    .dir(&dir)
                    .into_iter()
                    .filter(|e| !e.is_dir)
                    .map(|e| e.name)
                    .filter(|n| {
                        let n = n.as_encoded_bytes();
                        !n.is_empty() && !n.contains(&b'.') && !n.ends_with(b"~")
                    })
                    .collect();
                names.sort_by(|a, b| a.as_encoded_bytes().cmp(b.as_encoded_bytes()));
                for n in names {
                    xinetd_file(cx, &dir.join(n), depth + 1, conf);
                }
            }
            (None, [b"include", file]) => xinetd_file(cx, &include_path(file), depth + 1, conf),
            (Some(_), [b"{"]) | (None, _) => {}
            (Some(_), [b"}"]) => {
                let (name, attrs) = block.take().unwrap_or_default();
                match name {
                    Some(name) => conf.services.push(Service { rel: rel.to_path_buf(), name, attrs }),
                    None => defaults(&attrs, conf),
                }
            }
            (Some((_, attrs)), [key, op, rest @ ..]) => {
                let (key, value) = (lossy(key), lossy(&rest.join(&b' ')));
                let list = matches!(key.as_str(), "enabled" | "disabled");
                match *op {
                    b"=" => {
                        attrs.insert(key, value);
                    }
                    // The list attributes that matter here: the rest xinetd
                    // either modifies harmlessly or rejects.
                    b"+=" if list => {
                        let merged = attrs.get(&key).map(|v| format!("{v} {value}")).unwrap_or(value);
                        attrs.insert(key, merged);
                    }
                    b"-=" if list => {
                        let drop: Vec<&str> = value.split_whitespace().collect();
                        let kept: Vec<String> = attrs
                            .get(&key)
                            .map(|v| v.split_whitespace().filter(|w| !drop.contains(w)).map(String::from).collect())
                            .unwrap_or_default();
                        attrs.insert(key, kept.join(" "));
                    }
                    _ => {}
                }
            }
            (Some(_), _) => {}
        }
    }
}

fn defaults(attrs: &BTreeMap<String, String>, conf: &mut Xinetd) {
    let ids = |v: &String| v.split_whitespace().map(String::from).collect::<Vec<_>>();
    if let Some(v) = attrs.get("enabled") {
        conf.enabled = Some(ids(v));
    }
    if let Some(v) = attrs.get("disabled") {
        conf.disabled.extend(ids(v));
    }
}

/// A path xinetd names, root-relative.
fn include_path(p: &[u8]) -> PathBuf {
    PathBuf::from(lossy(p).trim_start_matches('/'))
}

// ---------------------------------------------------------------- inetd ----

/// /etc/inetd.conf, one service per line: name, socket type, protocol, wait,
/// user (`user[.group]` or `user[:group]`), server, then the argv, whose
/// first word is argv[0]. `internal` is inetd's own code. A line that is
/// commented out, as update-inetd disables one with `#<off>#`, is a comment.
fn inetd(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let rel = Path::new(INETD_CONF);
    let Some(bytes) = cx.read_capped(rel, FILE_CAP) else { return };
    let mut used = BTreeMap::new();
    for raw in bytes.split(|b| *b == b'\n') {
        let line = raw.trim_ascii();
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let words: Vec<&[u8]> = line.split(u8::is_ascii_whitespace).filter(|w| !w.is_empty()).collect();
        let [service, socket_type, protocol, wait, user, server, argv @ ..] = words.as_slice() else { continue };
        let name = uniq(&mut used, rel, format!("{}/{}", lossy(service), lossy(protocol)));
        let mut e = cx.entry(Kind::InetdService, rel, name);
        e.trigger = Trigger::NetworkEvent;
        e.enabled = Enablement::Enabled;
        e.note("daemon", "inetd");
        e.note("socket_type", lossy(socket_type));
        e.note("wait", lossy(wait));
        let account = user.split(|b| *b == b'.' || *b == b':').next().unwrap_or_default();
        e.principal = Some(lossy(account));
        if *server != b"internal" {
            // argv[0] is part of the argv. Under tcpd it is the program tcpd
            // runs, which is what the wrapper look-through needs to see.
            let command = [*server].into_iter().chain(argv.iter().copied()).collect::<Vec<_>>().join(&b' ');
            e.command = Some(command);
            e.target_path = Some(PathBuf::from(lossy(server)));
        }
        if std::str::from_utf8(line).is_err() {
            e.flag(Flag::EncodingAnomaly);
        }
        out.push(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan};

    fn tree(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("unbidden-inetd-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
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
        crate::scan::run(&root, &Options { deep: false }, &[Box::new(Inetd)])
    }

    fn one<'a>(s: &'a Scan, name: &str) -> &'a Entry {
        let found: Vec<_> = s.entries.iter().filter(|e| e.name == name).collect();
        assert_eq!(found.len(), 1, "{name}: {:?}", s.entries.iter().map(|e| &e.name).collect::<Vec<_>>());
        found[0]
    }

    fn service(name: &str, server: &str, extra: &str) -> Vec<u8> {
        format!(
            "# a comment\nservice {name}\n{{\n\tsocket_type = stream\n\tprotocol = tcp\n\twait = no\n\tuser = root\n\tserver = {server}\n{extra}}}\n"
        )
        .into_bytes()
    }

    #[test]
    fn xinetd_reads_what_xinetd_loads_and_says_what_is_off() {
        let d = tree("xinetd");
        put(&d, "usr/sbin/xinetd", b"");
        put(&d, "etc/xinetd.conf", b"defaults\n{\n\tdisabled = listed\n\tdisabled += other\n}\nincludedir /etc/xinetd.d\n");
        put(&d, "etc/xinetd.d/telnet", &service("telnet", "/usr/sbin/in.telnetd", "\tserver_args = -h\n\tserver_args += -x\n"));
        put(&d, "etc/xinetd.d/telnet.bak", &service("bak", "/tmp/bak", ""));
        put(&d, "etc/xinetd.d/tilde~", &service("tilde", "/tmp/tilde", ""));
        put(&d, "etc/xinetd.d/off", &service("off", "/tmp/off", "\tdisable = yes\n"));
        put(&d, "etc/xinetd.d/listed", &service("listed", "/tmp/listed", ""));
        put(
            &d,
            "etc/xinetd.d/echo",
            b"service echo\n{\n\ttype = INTERNAL\n\tid = echo-stream\n\tdisable = yes\n}\nservice echo\n{\n\ttype = INTERNAL\n\tid = echo-dgram\n}\n",
        );
        let s = scan(&d);
        assert!(s.entries.iter().all(|e| e.name != "bak" && e.name != "tilde"), "a dotted or ~ name never loads");

        let telnet = one(&s, "telnet");
        assert_eq!(telnet.kind, Kind::InetdService);
        assert_eq!((telnet.trigger, telnet.enabled), (Trigger::NetworkEvent, Enablement::Enabled));
        assert_eq!(telnet.principal.as_deref(), Some("root"));
        assert_eq!(telnet.target_path, Some(PathBuf::from("/usr/sbin/in.telnetd")));
        assert_eq!(telnet.command.as_deref(), Some(b"/usr/sbin/in.telnetd -h".as_slice()), "server_args takes no +=");

        assert_eq!(one(&s, "off").enabled, Enablement::Disabled);
        assert_eq!(one(&s, "listed").enabled, Enablement::Disabled, "defaults' disabled list");
        let stream = one(&s, "echo (echo-stream)");
        assert_eq!((stream.enabled, stream.target_path.clone()), (Enablement::Disabled, None), "INTERNAL runs no program");
        assert_eq!(one(&s, "echo (echo-dgram)").enabled, Enablement::Enabled);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_defaults_enabled_list_switches_off_everything_it_does_not_name() {
        let d = tree("enabled");
        put(&d, "usr/sbin/xinetd", b"");
        put(&d, "etc/xinetd.conf", b"defaults\n{\n\tenabled = ftp\n}\ninclude /etc/xinetd.d/all\n");
        put(&d, "etc/xinetd.d/all", &[service("ftp", "/usr/sbin/ftpd", ""), service("rsh", "/usr/sbin/in.rshd", "")].concat());
        let s = scan(&d);
        assert_eq!(one(&s, "ftp").enabled, Enablement::Enabled);
        assert_eq!(one(&s, "rsh").enabled, Enablement::Disabled);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn inetd_conf_lines_name_their_program_and_account() {
        let d = tree("inetd");
        put(&d, "usr/sbin/inetd", b"");
        put(
            &d,
            "etc/inetd.conf",
            b"# comment\n#<off># telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.telnetd\n\
              telnet  stream  tcp  nowait  root.root  /usr/sbin/tcpd  /usr/sbin/in.telnetd\n\
              ftp stream tcp nowait nobody:nogroup /usr/sbin/ftpd ftpd -l\n\
              echo stream tcp nowait root internal\n\
              short line\n",
        );
        let s = scan(&d);
        assert_eq!(s.entries.len(), 3);
        let telnet = one(&s, "telnet/tcp");
        assert_eq!(telnet.principal.as_deref(), Some("root"));
        assert_eq!(telnet.command.as_deref(), Some(b"/usr/sbin/tcpd /usr/sbin/in.telnetd".as_slice()));
        assert_eq!(one(&s, "ftp/tcp").principal.as_deref(), Some("nobody"));
        assert_eq!(one(&s, "echo/tcp").target_path, None);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_configuration_without_its_daemon_starts_nothing() {
        let d = tree("nodaemon");
        put(&d, "etc/xinetd.conf", b"includedir /etc/xinetd.d\n");
        put(&d, "etc/xinetd.d/telnet", &service("telnet", "/usr/sbin/in.telnetd", ""));
        put(&d, "etc/inetd.conf", b"telnet stream tcp nowait root /usr/sbin/in.telnetd in.telnetd\n");
        assert!(scan(&d).entries.is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
