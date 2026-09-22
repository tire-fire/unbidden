//! The Entry record's JSON form is the project's compatibility contract, and
//! the two things that can quietly break it are a collector changing what it
//! emits and a parser falling over on input it has not seen.
//!
//! Both are checked against one synthetic filesystem tree: a golden file that
//! fails on any unintended change to the record, and a mutation pass that
//! takes the same tree apart byte by byte and requires the scan to survive.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use unbidden::scan::{Options, Scan, Status};
use unbidden::{collect, enrich, scan};
use unbidden::root::Root;

/// One file per mechanism class, chosen so that every collector has
/// something to find and the interesting flags are all exercised.
fn build_tree(dir: &Path) {
    // Explicit modes, because `fs::write` takes them from the runner's umask
    // and `mode` is part of the record this file pins.
    let w = |rel: &str, body: &[u8]| {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, PermissionsExt::from_mode(0o644)).unwrap();
    };
    let exec = |rel: &str| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join(rel), PermissionsExt::from_mode(0o755)).unwrap();
    };

    w("etc/os-release", b"ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n");
    w("etc/hostname", b"golden\n");

    // Whoever runs the tests owns every file this tree creates, so a fixed
    // uid in passwd would make OwnerMismatch fire on one machine and not
    // another — which is what broke this record the first time it ran in CI.
    // alice owns her files by construction; bob never can, so both sides of
    // the flag are pinned rather than inherited from the runner.
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata(dir.join("etc/hostname")).unwrap().uid();
    w(
        "etc/passwd",
        format!(
            "root:x:0:0:root:/root:/bin/bash\n\
             alice:x:{uid}:{uid}::/home/alice:/bin/zsh\n\
             bob:x:65530:65530::/home/bob:/bin/sh\n"
        )
        .as_bytes(),
    );
    w("home/bob/.bashrc", b"export PATH=$PATH:/opt/bob/bin\n");

    // systemd: a vendor unit, an attacker's unit, an enabling symlink, a
    // drop-in, and a masked unit.
    w("usr/lib/systemd/system/ssh.service", b"[Unit]\nDescription=OpenSSH\n[Service]\nExecStart=/usr/sbin/sshd -D\n[Install]\nWantedBy=multi-user.target\n");
    w("etc/systemd/system/telemetry.service", b"[Service]\nExecStart=/opt/telemetry --quiet\nEnvironment=LD_PRELOAD=/tmp/hook.so\nUser=root\n[Install]\nWantedBy=multi-user.target\n");
    w("etc/systemd/system/ssh.service.d/override.conf", b"[Service]\nExecStartPre=/opt/pre.sh\n");
    std::fs::create_dir_all(dir.join("etc/systemd/system/multi-user.target.wants")).unwrap();
    std::os::unix::fs::symlink("/etc/systemd/system/telemetry.service", dir.join("etc/systemd/system/multi-user.target.wants/telemetry.service")).unwrap();
    std::os::unix::fs::symlink("/dev/null", dir.join("etc/systemd/system/rsyslog.service")).unwrap();
    w("usr/lib/systemd/system/backup.timer", b"[Timer]\nOnCalendar=daily\nPersistent=true\n[Install]\nWantedBy=timers.target\n");

    // cron, including an environment assignment above a job.
    w("etc/crontab", b"SHELL=/bin/sh\nMAILTO=root\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n");
    w("etc/cron.d/agent", b"LD_PRELOAD=/tmp/hook.so\n@reboot root /usr/local/bin/agent --daemon\n");
    w("etc/cron.daily/logrotate", b"#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n");
    exec("etc/cron.daily/logrotate");

    w("etc/profile", b"export PATH=/usr/local/bin:$PATH\n. /etc/profile.d/lang.sh\n");
    w("etc/profile.d/lang.sh", b"export LANG=C.UTF-8\n");
    w("home/alice/.bashrc", b"export LD_PRELOAD=/home/alice/.cache/x.so\nalias ls='ls --color'\n");
    w("etc/ld.so.preload", b"/usr/lib/libsnoop.so\n# a comment\n");

    w("etc/xdg/autostart/nm-applet.desktop", b"[Desktop Entry]\nType=Application\nName=Network\nExec=/usr/bin/nm-applet --indicator\n");
    w("home/alice/.config/autostart/updater.desktop", b"[Desktop Entry]\nType=Application\nName=Updater\nExec=/home/alice/.local/bin/upd\nX-GNOME-Autostart-enabled=true\n");

    w("etc/udev/rules.d/99-custom.rules", b"ACTION==\"add\", SUBSYSTEM==\"usb\", RUN+=\"/usr/local/bin/on-usb.sh\"\n");
    w("etc/modules-load.d/extra.conf", b"# load these\nvboxdrv\n");
    w("etc/modprobe.d/evil.conf", b"install nf_tables /bin/sh -c '/tmp/stage.sh; /sbin/modprobe --ignore-install nf_tables'\n");

    w("etc/pam.d/sshd", b"auth       required     pam_unix.so\nsession    optional     pam_exec.so seteuid /usr/local/sbin/notify\n");
    w("home/alice/.ssh/authorized_keys", b"command=\"/usr/local/bin/wrap, --strict\",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialHere alice@host\n");
    w("etc/ssh/sshd_config", b"PermitRootLogin no\nForceCommand /usr/local/bin/shell-wrap\n");
    w("etc/sudoers", b"root ALL=(ALL:ALL) ALL\nalice ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n");

    w("etc/rc.local", b"#!/bin/sh\n/opt/boot-hook.sh\nexit 0\n");
    exec("etc/rc.local");
    w("etc/init.d/legacy", b"#!/bin/sh\n### BEGIN INIT INFO\n# Provides: legacy\n# Default-Start: 2 3 4 5\n### END INIT INFO\nexec /usr/sbin/legacyd\n");
    exec("etc/init.d/legacy");
    std::fs::create_dir_all(dir.join("etc/rc2.d")).unwrap();
    std::os::unix::fs::symlink("../init.d/legacy", dir.join("etc/rc2.d/S20legacy")).unwrap();

    // A package database, so provenance has something to say.
    w("var/lib/dpkg/status", b"Package: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.2p1-2\nConffiles:\n /etc/ssh/sshd_config 00000000000000000000000000000000\n\nPackage: dash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 0.5.12-2\n\n");
    w("var/lib/dpkg/info/openssh-server.list", b"/usr/lib/systemd/system/ssh.service\n/etc/ssh/sshd_config\n");
    w("var/lib/dpkg/info/dash.list", b"/bin/sh\n");
    let digest = {
        use md5::Digest as _;
        let mut h = md5::Md5::new();
        h.update(b"[Unit]\nDescription=OpenSSH\n[Service]\nExecStart=/usr/sbin/sshd -D\n[Install]\nWantedBy=multi-user.target\n");
        format!("{:x}", h.finalize())
    };
    w("var/lib/dpkg/info/openssh-server.md5sums", format!("{digest}  usr/lib/systemd/system/ssh.service\n").as_bytes());
    let sh_digest = {
        use md5::Digest as _;
        let mut h = md5::Md5::new();
        h.update(b"ELF-ish\n");
        format!("{:x}", h.finalize())
    };
    w("var/lib/dpkg/info/dash.md5sums", format!("{sh_digest}  bin/sh\n").as_bytes());

    // Targets that exist, so TargetMissing means something when it appears.
    for bin in ["usr/sbin/sshd", "usr/bin/nm-applet", "usr/local/bin/agent"] {
        w(bin, b"#!/bin/sh\n");
        exec(bin);
    }

    // The interpreter every script in this tree names. Packaged and intact,
    // so the chained rows it produces are suppressed — which is the half of
    // interpreter chaining that has to stay quiet. /usr/sbin/legacyd, which
    // the init script execs, is owned by nobody and is the half that must
    // not be.
    w("bin/sh", b"ELF-ish\n");
    exec("bin/sh");
}

fn scan_tree(dir: &Path) -> Scan {
    let root = Root::at(dir).unwrap();
    let collectors = collect::all();
    let mut s = scan::run(&root, &Options { deep: false }, &collectors);
    enrich::enrich(&root, &mut s);
    enrich::enrich_late(&root, &mut s);
    s
}

/// Everything that legitimately differs between two machines: the scan root's
/// own path, the uid the tests run as, timestamps, and the kernel underneath.
fn normalise(scan: &Scan, dir: &Path) -> serde_json::Value {
    let root_text = dir.to_string_lossy().into_owned();
    let mut value = serde_json::to_value(scan).unwrap();
    scrub(&mut value, &root_text);
    value
}

fn scrub(value: &mut serde_json::Value, root_text: &str) {
    match value {
        serde_json::Value::String(s) => {
            if s.contains(root_text) {
                *s = s.replace(root_text, "<ROOT>");
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(|v| scrub(v, root_text)),
        serde_json::Value::Object(map) => {
            for key in ["scan_time", "mtime", "owner_uid", "kernel", "privileged", "unbidden_version"] {
                if let Some(v) = map.get_mut(key) {
                    *v = serde_json::Value::String("<normalised>".into());
                }
            }
            for (_, v) in map.iter_mut() {
                scrub(v, root_text);
            }
        }
        _ => {}
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("unbidden-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn collector_output_matches_the_golden_record() {
    let dir = tmpdir("golden");
    build_tree(&dir);
    let scan = scan_tree(&dir);

    // Nothing may fail on input this ordinary.
    for c in &scan.header.collectors {
        assert!(
            !matches!(c.status, Status::Failed { .. }),
            "collector {} failed on the golden tree: {:?}",
            c.name,
            c.status
        );
    }

    let produced = serde_json::to_string_pretty(&normalise(&scan, &dir)).unwrap();
    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden.json");

    if std::env::var("UNBIDDEN_BLESS").is_ok() {
        std::fs::write(&golden_path, format!("{produced}\n")).unwrap();
        eprintln!("golden record rewritten: {}", golden_path.display());
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }

    let expected = std::fs::read_to_string(&golden_path)
        .unwrap_or_else(|e| panic!("{}: {e}. Run with UNBIDDEN_BLESS=1 to create it.", golden_path.display()));

    if expected.trim() != produced.trim() {
        let diff = first_difference(expected.trim(), produced.trim());
        panic!(
            "collector output no longer matches tests/golden.json.\n{diff}\n\
             If the change is intended, re-run with UNBIDDEN_BLESS=1 and review the diff before committing."
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

fn first_difference(expected: &str, produced: &str) -> String {
    let (mut e, mut p) = (expected.lines(), produced.lines());
    let mut line = 0;
    loop {
        line += 1;
        match (e.next(), p.next()) {
            (Some(a), Some(b)) if a == b => continue,
            (Some(a), Some(b)) => return format!("first difference at line {line}:\n  golden:   {a}\n  produced: {b}"),
            (Some(a), None) => return format!("golden has extra line {line}: {a}"),
            (None, Some(b)) => return format!("produced has extra line {line}: {b}"),
            (None, None) => return "files differ only in trailing whitespace".into(),
        }
    }
}

/// Every parser reads files an adversary may have authored. This takes the
/// golden tree apart in a few thousand deterministic ways and requires that
/// the scan still completes with no collector panicking.
#[test]
fn mutated_input_never_kills_a_collector() {
    let dir = tmpdir("mutate");
    build_tree(&dir);

    let mut targets: Vec<PathBuf> = Vec::new();
    collect_files(&dir, &mut targets);
    targets.sort();
    assert!(targets.len() > 15, "the tree should have plenty to break");

    let originals: BTreeMap<PathBuf, Vec<u8>> =
        targets.iter().map(|p| (p.clone(), std::fs::read(p).unwrap_or_default())).collect();

    let mut rng: u64 = 0x5eed_1234_abcd_ef01;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };

    for round in 0..120u32 {
        for (path, original) in &originals {
            if original.is_empty() {
                continue;
            }
            let mut bytes = original.clone();
            match round % 4 {
                // Truncate anywhere, including to nothing.
                0 => bytes.truncate((next() as usize) % (original.len() + 1)),
                // Corrupt a byte, which is how invalid UTF-8 and stray NULs
                // arrive in practice.
                1 => {
                    let at = (next() as usize) % original.len();
                    bytes[at] = (next() % 256) as u8;
                }
                // Splice in bytes no parser expects.
                2 => {
                    let at = (next() as usize) % original.len();
                    bytes.splice(at..at, [0x00, 0xff, 0xfe, b'\n', b'\\', b'"', b'=', b',']);
                }
                // A line far longer than anything real.
                _ => {
                    let at = (next() as usize) % original.len();
                    bytes.splice(at..at, std::iter::repeat_n(b'A', 100_000));
                }
            }
            std::fs::write(path, &bytes).unwrap();
        }

        let scan = scan_tree(&dir);
        for c in &scan.header.collectors {
            if let Status::Failed { error } = &c.status {
                panic!("round {round}: collector {} panicked on mutated input: {error}", c.name);
            }
        }
    }

    std::fs::remove_dir_all(&dir).unwrap();
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let path = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => collect_files(&path, out),
            Ok(t) if t.is_file() => out.push(path),
            _ => {}
        }
    }
}
