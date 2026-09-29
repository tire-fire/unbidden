//! What goes into the initramfs and what runs to build it, read from the
//! sources rather than the built image: the image is a compressed archive
//! the spec leaves unparsed, but every byte in it came from a file here.
//!
//! initramfs-tools 0.142 (mkinitramfs, hook-functions): at every image
//! build, as root, each hook in /usr/share/initramfs-tools/hooks and
//! /etc/initramfs-tools/hooks whose name holds only letters, digits, `.`,
//! `_` and `-`, that is a regular executable file, and that `sh -n`
//! accepts (not checked here), in prerequisite order. The boot-time
//! scripts, /usr/share/initramfs-tools/scripts and /etc/initramfs-tools/
//! scripts, are copied whole into the image; at boot the same name rule
//! picks the executables of each stage directory, and the files at the top
//! (functions, local, nfs) are sourced by them. dracut 108 (dracut,
//! dracut-init.sh): at every build, as root, each `*.conf` of
//! /etc/dracut.conf.d and /usr/lib/dracut/dracut.conf.d and /etc/
//! dracut.conf is sourced as shell, a name in /etc replacing the same
//! name in /usr/lib; each module directory of /usr/lib/dracut/modules.d
//! has its module-setup.sh sourced, whose check() decides inclusion and
//! whose install() copies files into the image. DKMS 3 (dkms): at every
//! kernel install, as root, /etc/dkms/framework.conf and framework.conf.d/
//! *.conf are sourced, and each registered module's dkms.conf is sourced
//! with its PRE_BUILD, POST_BUILD, PRE_INSTALL, POST_INSTALL, POST_ADD and
//! POST_REMOVE scripts run.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Initramfs;

const CAP: usize = 256 * 1024;

impl Collector for Initramfs {
    fn name(&self) -> &'static str {
        "initramfs"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        initramfs_tools(cx, &mut out);
        dracut(cx, &mut out);
        dkms(cx, &mut out);
        out
    }
}

fn file_name(rel: &Path) -> String {
    rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

fn sorted_files(cx: &mut Ctx, dir: &Path) -> Vec<PathBuf> {
    let names: Vec<_> = cx.dir(dir).into_iter().filter(|e| !e.is_dir).map(|e| e.name).collect();
    names.into_iter().map(|n| dir.join(n)).collect()
}

fn sorted_dirs(cx: &mut Ctx, dir: &Path) -> Vec<PathBuf> {
    let names: Vec<_> = cx.dir(dir).into_iter().filter(|e| e.is_dir).map(|e| e.name).collect();
    names.into_iter().map(|n| dir.join(n)).collect()
}

/// hook-functions' `set_initlist` name rule.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn entry(cx: &mut Ctx, rel: &Path, name: String, tool: &str, trigger: Trigger, installed: bool) -> Entry {
    let mut e = cx.entry(Kind::InitramfsHook, rel, name);
    e.trigger = trigger;
    e.principal = Some("root".into());
    e.enabled = Enablement::Enabled;
    e.note("run_by", tool);
    e.target_path = Some(cx.root.abs(rel));
    if !installed {
        e.enabled = Enablement::Disabled;
        e.note("not_run", format!("{tool} is not installed"));
    }
    e
}

/// mkinitramfs's `maybe_add_conf` rule for conf.d: a name that starts with a
/// letter or digit, holds only letters, digits, `.`, `_` and `-`, and is not
/// a `.dpkg-*` leftover.
fn conf_name(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) && plain_name(name) && !name.contains(".dpkg-")
}

/// The shell fragments mkinitramfs sources, as root, into its own shell at
/// every build: initramfs.conf, then conf.d (a name in /etc replacing the same
/// name under /usr/share), then the packages' conf-hooks.d. Hooks are separate
/// processes, so only the variables mkinitramfs exports reach them (MODULES,
/// BUSYBOX, RESUME and a few more); the file itself runs as root either way.
fn initramfs_tools_conf(cx: &mut Ctx, out: &mut Vec<Entry>, installed: bool) {
    let mut files: Vec<(PathBuf, String, Option<&'static str>)> = Vec::new();
    files.push((PathBuf::from("etc/initramfs-tools/initramfs.conf"), "initramfs.conf".into(), None));
    let etc_names: BTreeSet<String> = sorted_files(cx, Path::new("etc/initramfs-tools/conf.d")).iter().map(|r| file_name(r)).collect();
    for rel in sorted_files(cx, Path::new("usr/share/initramfs-tools/conf.d")) {
        let name = file_name(&rel);
        let why = etc_names.contains(&name).then_some("a file of this name in /etc/initramfs-tools/conf.d is read instead");
        files.push((rel, format!("conf.d/{name}"), why));
    }
    for rel in sorted_files(cx, Path::new("etc/initramfs-tools/conf.d")) {
        let name = file_name(&rel);
        files.push((rel, format!("conf.d/{name}"), None));
    }
    for rel in sorted_files(cx, Path::new("usr/share/initramfs-tools/conf-hooks.d")) {
        let name = file_name(&rel);
        files.push((rel, format!("conf-hooks.d/{name}"), None));
    }
    for (rel, label, why) in files {
        let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
        if !meta.is_file {
            continue;
        }
        let mut e = entry(cx, &rel, format!("initramfs-tools:conf:{label}"), "mkinitramfs", Trigger::PackageOp, installed);
        e.note("runs_when", "every initramfs build: sourced as shell by mkinitramfs, as root");
        if label.starts_with("conf.d/") && !conf_name(&file_name(&rel)) {
            e.enabled = Enablement::Disabled;
            e.note("not_read", "mkinitramfs sources only names of letters, digits, ., _ and -, not .dpkg-* leftovers");
        } else if let Some(w) = why {
            e.enabled = Enablement::Disabled;
            e.note("not_read", w);
        }
        out.push(e);
    }
}

fn initramfs_tools(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/sbin/mkinitramfs");
    initramfs_tools_conf(cx, out, installed);
    for base in ["usr/share/initramfs-tools", "etc/initramfs-tools"] {
        for rel in sorted_files(cx, &Path::new(base).join("hooks")) {
            let name = file_name(&rel);
            let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
            if !meta.is_file {
                continue;
            }
            let mut e = entry(cx, &rel, format!("initramfs-tools:hook:{name}"), "mkinitramfs", Trigger::PackageOp, installed);
            e.note("runs_when", "every initramfs build, before the image is packed");
            e.note("syntax", "sh -n is not checked here; a hook it rejects is skipped");
            if !plain_name(&name) {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "mkinitramfs runs only names of letters, digits, ., _ and -");
            } else if meta.mode & 0o111 == 0 {
                e.enabled = Enablement::Disabled;
                e.note("not_run", "not executable");
            }
            out.push(e);
        }
        // scripts/: the stage directories and the libraries beside them.
        let scripts = Path::new(base).join("scripts");
        let mut files: Vec<(PathBuf, Option<String>)> = sorted_files(cx, &scripts).into_iter().map(|f| (f, None)).collect();
        for stage in sorted_dirs(cx, &scripts) {
            let stage_name = file_name(&stage);
            files.extend(sorted_files(cx, &stage).into_iter().map(|f| (f, Some(stage_name.clone()))));
        }
        for (rel, stage) in files {
            let name = file_name(&rel);
            let Ok(meta) = cx.root.stat_follow(&rel) else { continue };
            if !meta.is_file {
                continue;
            }
            let label = match &stage {
                Some(s) => format!("initramfs-tools:{s}:{name}"),
                None => format!("initramfs-tools:scripts:{name}"),
            };
            let mut e = entry(cx, &rel, label, "the initramfs", Trigger::Boot, installed);
            e.note("copied_into", "every initramfs this host builds");
            match stage {
                Some(s) => {
                    e.note("stage", s);
                    e.note("runs_when", "at boot, as root, before the root filesystem is mounted");
                    if !plain_name(&name) {
                        e.enabled = Enablement::Disabled;
                        e.note("not_run", "the image runs only names of letters, digits, ., _ and -");
                    } else if meta.mode & 0o111 == 0 {
                        e.enabled = Enablement::Disabled;
                        e.note("not_run", "not executable");
                    }
                }
                None => e.note("runs_when", "sourced by the stage scripts at boot"),
            }
            out.push(e);
        }
    }
}

fn dracut(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/bin/dracut");
    // Configuration, sourced as shell; a name in /etc hides the same name
    // under /usr/lib.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut confs: Vec<(PathBuf, Option<String>)> = vec![(PathBuf::from("etc/dracut.conf"), None)];
    for dir in ["etc/dracut.conf.d", "usr/lib/dracut/dracut.conf.d"] {
        for rel in sorted_files(cx, Path::new(dir)) {
            let name = file_name(&rel);
            if !name.ends_with(".conf") {
                continue;
            }
            let why = (!seen.insert(name.clone())).then(|| "a file of this name in /etc/dracut.conf.d is read instead".to_string());
            confs.push((rel, why));
        }
    }
    for (rel, why) in confs {
        let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
        let mut e = entry(cx, &rel, format!("dracut:conf:{}", file_name(&rel)), "dracut", Trigger::PackageOp, installed);
        e.note("runs_when", "every initramfs build: sourced as shell");
        for line in String::from_utf8_lossy(&bytes).lines() {
            let t = line.trim();
            for key in ["install_items", "install_optional_items", "add_dracutmodules", "force_add_dracutmodules", "dracutmodules"] {
                if let Some(v) = t.strip_prefix(key).and_then(|r| r.trim_start().strip_prefix("+=").or_else(|| r.trim_start().strip_prefix('='))) {
                    e.note(key, v.trim().trim_matches('"').trim());
                }
            }
        }
        if let Some(w) = why {
            e.enabled = Enablement::Disabled;
            e.note("not_read", w);
        }
        out.push(e);
    }
    for module in sorted_dirs(cx, Path::new("usr/lib/dracut/modules.d")) {
        let name = file_name(&module);
        // A module directory is NN<name>. Split by bytes, not by a byte index
        // into text: a directory named `9€bad` has no boundary at 2, and the
        // slice used to panic the whole collector.
        let Some((order, module_name)) = name.split_at_checked(2) else { continue };
        if module_name.is_empty() || !order.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let setup = module.join("module-setup.sh");
        let rel = if cx.root.exists(&setup) { setup } else { module.join("check") };
        if !cx.root.stat_follow(&rel).is_ok_and(|m| m.is_file) {
            continue;
        }
        let mut e = entry(cx, &rel, format!("dracut:module:{module_name}"), "dracut", Trigger::PackageOp, installed);
        e.note("runs_when", "every initramfs build: check() decides inclusion, install() copies into the image");
        out.push(e);
    }
}

fn dkms(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/sbin/dkms") || cx.root.exists("usr/bin/dkms");
    let mut files = vec![PathBuf::from("etc/dkms/framework.conf")];
    files.extend(sorted_files(cx, Path::new("etc/dkms/framework.conf.d")).into_iter().filter(|f| file_name(f).ends_with(".conf")));
    for rel in files {
        if !cx.root.stat_follow(&rel).is_ok_and(|m| m.is_file) {
            continue;
        }
        let mut e = cx.entry(Kind::PkgHook, &rel, format!("dkms:framework:{}", file_name(&rel)));
        e.trigger = Trigger::PackageOp;
        e.principal = Some("root".into());
        e.enabled = Enablement::Enabled;
        e.note("hook", "sourced as shell by dkms on every run");
        e.target_path = Some(cx.root.abs(&rel));
        if !installed {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "dkms is not installed");
        }
        out.push(e);
    }
    // Registered modules' dkms.conf, through the tree's `source` link and
    // straight from /usr/src, one entry per file.
    let mut confs: BTreeSet<PathBuf> = BTreeSet::new();
    for module in sorted_dirs(cx, Path::new("var/lib/dkms")) {
        for version in sorted_dirs(cx, &module) {
            let conf = version.join("source/dkms.conf");
            if let Ok(resolved) = cx.root.resolve(&conf)
                && cx.root.stat_follow(&resolved).is_ok_and(|m| m.is_file)
            {
                confs.insert(resolved);
            }
        }
    }
    for src in sorted_dirs(cx, Path::new("usr/src")) {
        let conf = src.join("dkms.conf");
        if cx.root.stat_follow(&conf).is_ok_and(|m| m.is_file) {
            confs.insert(conf);
        }
    }
    const HOOKS: [&str; 8] = ["PRE_BUILD", "POST_BUILD", "PRE_INSTALL", "POST_INSTALL", "POST_ADD", "POST_REMOVE", "PRE_REMOVE", "MAKE"];
    for rel in confs {
        let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
        let module = rel.parent().map(file_name).unwrap_or_default();
        let mut e = cx.entry(Kind::PkgHook, &rel, format!("dkms:{module}"));
        e.trigger = Trigger::PackageOp;
        e.principal = Some("root".into());
        e.enabled = Enablement::Enabled;
        e.note("hook", "sourced as shell by dkms at every kernel install; its scripts run from the module's source directory");
        e.target_path = Some(cx.root.abs(&rel));
        for line in String::from_utf8_lossy(&bytes).lines() {
            let t = line.trim();
            for h in HOOKS {
                let Some(rest) = t.strip_prefix(h) else { continue };
                let rest = rest.trim_start_matches(|c: char| c.is_ascii_digit() || c == '[' || c == ']');
                if let Some(v) = rest.strip_prefix('=') {
                    e.note(h, v.trim().trim_matches('"').trim());
                }
            }
        }
        if !installed {
            e.enabled = Enablement::Disabled;
            e.note("not_run", "dkms is not installed");
        }
        out.push(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan};

    fn put(dir: &Path, rel: &str, body: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Initramfs)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    #[test]
    fn mkinitramfs_sources_its_configuration_as_root_at_every_build() {
        let d = crate::testing::Tree::new("initramfs-conf");
        put(&d, "usr/sbin/mkinitramfs", b"", 0o755);
        put(&d, "etc/initramfs-tools/initramfs.conf", b"MODULES=most\n", 0o644);
        put(&d, "etc/initramfs-tools/conf.d/50-local", b"export PATH=/tmp:$PATH\n", 0o644);
        put(&d, "etc/initramfs-tools/conf.d/50-local.dpkg-old", b"x\n", 0o644);
        put(&d, "etc/initramfs-tools/conf.d/.hidden", b"x\n", 0o644);
        put(&d, "usr/share/initramfs-tools/conf.d/50-local", b"# vendor\n", 0o644);
        put(&d, "usr/share/initramfs-tools/conf.d/60-vendor", b"# vendor\n", 0o644);
        put(&d, "usr/share/initramfs-tools/conf-hooks.d/zz-pkg", b"# pkg\n", 0o644);
        let s = scan(&d);
        let get = |name: &str| s.entries.iter().find(|e| e.name == format!("initramfs-tools:conf:{name}")).unwrap_or_else(|| panic!("no {name}"));
        assert_eq!(get("initramfs.conf").enabled, Enablement::Enabled);
        assert_eq!(get("initramfs.conf").raw["run_by"], "mkinitramfs");
        let local: Vec<_> = s.entries.iter().filter(|e| e.name == "initramfs-tools:conf:conf.d/50-local").collect();
        assert_eq!(local.len(), 2, "both copies are reported");
        assert!(local.iter().any(|e| e.enabled == Enablement::Enabled && e.source.starts_with(d.join("etc"))));
        assert!(local.iter().any(|e| e.enabled == Enablement::Disabled && e.raw["not_read"].contains("/etc/initramfs-tools/conf.d")));
        assert_eq!(get("conf.d/60-vendor").enabled, Enablement::Enabled);
        assert_eq!(get("conf-hooks.d/zz-pkg").enabled, Enablement::Enabled);
        assert_eq!(get("conf.d/50-local.dpkg-old").enabled, Enablement::Disabled);
        assert_eq!(get("conf.d/.hidden").enabled, Enablement::Disabled);
    }

    #[test]
    fn a_module_directory_named_in_multibyte_text_cannot_fail_the_collector() {
        let d = crate::testing::Tree::new("initramfs-utf8");
        put(&d, "usr/bin/dracut", b"", 0o755);
        put(&d, "usr/lib/dracut/modules.d/9\u{20ac}bad/module-setup.sh", b"", 0o755);
        put(&d, "usr/lib/dracut/modules.d/\u{20ac}9x/module-setup.sh", b"", 0o755);
        put(&d, "usr/lib/dracut/modules.d/98evil/module-setup.sh", b"install() { inst /opt/e /bin/e; }\n", 0o755);
        let s = scan(&d);
        let status = &s.header.collectors[0].status;
        assert!(matches!(status, crate::scan::Status::Complete), "a planted directory beside the real ones must not blind the collector: {status:?}");
        assert!(s.entries.iter().any(|e| e.name == "dracut:module:evil"), "the module beside it is still read");
    }

    #[test]
    fn what_builds_and_fills_the_initramfs_is_read() {
        let d = crate::testing::Tree::new("initramfs");
        put(&d, "usr/sbin/mkinitramfs", b"", 0o755);
        put(&d, "usr/share/initramfs-tools/hooks/resume", b"#!/bin/sh\n", 0o755);
        put(&d, "etc/initramfs-tools/hooks/beacon", b"#!/bin/sh\ncp /opt/b ${DESTDIR}/bin\n", 0o755);
        put(&d, "etc/initramfs-tools/hooks/notes.txt~", b"", 0o755);
        put(&d, "etc/initramfs-tools/hooks/quiet", b"#!/bin/sh\n", 0o644);
        put(&d, "etc/initramfs-tools/scripts/init-top/00run", b"#!/bin/sh\n/bin/b\n", 0o755);
        put(&d, "usr/share/initramfs-tools/scripts/functions", b"log_begin_msg() { :; }\n", 0o644);
        put(&d, "usr/bin/dracut", b"", 0o755);
        put(&d, "etc/dracut.conf.d/01-dist.conf", b"install_items+=\" /opt/x \"\n", 0o644);
        put(&d, "usr/lib/dracut/dracut.conf.d/01-dist.conf", b"add_dracutmodules+=\" fips \"\n", 0o644);
        put(&d, "usr/lib/dracut/dracut.conf.d/02-x.conf", b"compress=zstd\n", 0o644);
        put(&d, "usr/lib/dracut/modules.d/99evil/module-setup.sh", b"install() { inst /opt/e /bin/e; }\n", 0o755);
        put(&d, "usr/lib/dracut/modules.d/README", b"", 0o644);
        put(&d, "usr/sbin/dkms", b"", 0o755);
        put(&d, "etc/dkms/framework.conf", b"# x\n", 0o644);
        put(&d, "usr/src/evil-1.0/dkms.conf", b"PACKAGE_NAME=evil\nPACKAGE_VERSION=1.0\nPOST_INSTALL=\"post.sh\"\nPRE_BUILD=pre.sh\n", 0o644);
        std::fs::create_dir_all(d.join("var/lib/dkms/evil/1.0")).unwrap();
        std::os::unix::fs::symlink("/usr/src/evil-1.0", d.join("var/lib/dkms/evil/1.0/source")).unwrap();
        let s = scan(&d);
        let mut got: Vec<(&str, Enablement)> = s.entries.iter().map(|e| (e.name.as_str(), e.enabled)).collect();
        got.sort();
        assert_eq!(
            got,
            [
                ("dkms:evil-1.0", Enablement::Enabled),
                ("dkms:framework:framework.conf", Enablement::Enabled),
                ("dracut:conf:01-dist.conf", Enablement::Enabled),
                ("dracut:conf:01-dist.conf", Enablement::Disabled),
                ("dracut:conf:02-x.conf", Enablement::Enabled),
                ("dracut:module:evil", Enablement::Enabled),
                ("initramfs-tools:hook:beacon", Enablement::Enabled),
                ("initramfs-tools:hook:notes.txt~", Enablement::Disabled),
                ("initramfs-tools:hook:quiet", Enablement::Disabled),
                ("initramfs-tools:hook:resume", Enablement::Enabled),
                ("initramfs-tools:init-top:00run", Enablement::Enabled),
                ("initramfs-tools:scripts:functions", Enablement::Enabled),
            ],
            "the dkms.conf is one entry through the tree and /usr/src; the /etc dracut conf hides the /usr/lib one of its name"
        );
        let dk = s.entries.iter().find(|e| e.name == "dkms:evil-1.0").unwrap();
        assert_eq!((dk.raw["POST_INSTALL"].as_str(), dk.raw["PRE_BUILD"].as_str()), ("post.sh", "pre.sh"));
        let inst = s.entries.iter().find(|e| e.name == "dracut:conf:01-dist.conf" && e.enabled == Enablement::Enabled).unwrap();
        assert_eq!(inst.raw["install_items"], "/opt/x");
        assert_eq!(s.entries.iter().find(|e| e.name == "initramfs-tools:init-top:00run").unwrap().trigger, Trigger::Boot);
    }
}
