//! Plug-in registries: files that name a shared library an application
//! framework loads into its own process, as code, when it starts or converts
//! data. Each is read by the rule the framework uses, and the library it
//! names is resolved so its provenance can be judged.
//!
//! gconv (glibc iconv/gconv_parseconfdir.h): the `module from to file [cost]`
//! lines of `gconv-modules` and the `*.conf` files of `gconv-modules.d`
//! beside it, in the gconv directory (/usr/lib/<triplet>/gconv or
//! /usr/lib64/gconv). glibc loads a module when a program converts to or
//! from a charset it names, which nearly every program does; a relative file
//! is that directory's, and `.so` is appended if absent. p11-kit: the
//! `module: path` line of each `.module` file in /usr/share/p11-kit/modules
//! and /etc/pkcs11/modules, a PKCS#11 library loaded by anything that uses
//! one (gnutls, libssh, ssh's PKCS11Provider). EGL (libglvnd): the
//! `ICD.library_path` of each JSON in /usr/share/glvnd/egl_vendor.d. Vulkan
//! (the loader): the `ICD.library_path` of each JSON in vulkan/icd.d, and the
//! `layer.library_path` of each in implicit_layer.d, loaded into every
//! Vulkan program without being asked for. OpenCL (ocl-icd): each line of
//! each `.icd` file in /etc/OpenCL/vendors, a library loaded by every OpenCL
//! program. A relative library name is resolved on the loader's search path.

use std::path::{Path, PathBuf};

use crate::entry::{Enablement, Entry, Kind, Trigger};
use crate::scan::{Collector, Ctx};

pub struct Plugins;

const CAP: usize = 1 << 20;

impl Collector for Plugins {
    fn name(&self) -> &'static str {
        "plugins"
    }

    fn collect(&self, cx: &mut Ctx) -> Vec<Entry> {
        let mut out = Vec::new();
        let libdirs = library_dirs(cx);
        gconv(cx, &mut out);
        p11_kit(cx, &libdirs, &mut out);
        for (dir, framework, trigger) in [
            ("usr/share/glvnd/egl_vendor.d", "EGL", Trigger::Always),
            ("usr/share/vulkan/icd.d", "Vulkan", Trigger::Always),
            ("etc/vulkan/icd.d", "Vulkan", Trigger::Always),
            ("usr/share/vulkan/implicit_layer.d", "Vulkan", Trigger::Always),
            ("etc/vulkan/implicit_layer.d", "Vulkan", Trigger::Always),
        ] {
            icd_json(cx, Path::new(dir), framework, trigger, &libdirs, &mut out);
        }
        opencl(cx, &libdirs, &mut out);
        crate::entry::dedup_ids(&mut out);
        out
    }
}

/// Where a bare soname is looked for: the loader's configured directories
/// and its built-in trusted ones, the multiarch pair among them included.
fn library_dirs(cx: &mut Ctx) -> Vec<String> {
    let mut dirs: Vec<String> = super::ld_so_conf_dirs(cx).into_iter().map(|(d, _)| d.trim_start_matches('/').to_string()).collect();
    for d in ["lib", "usr/lib", "lib64", "usr/lib64"] {
        if !dirs.iter().any(|s| s == d) {
            dirs.push(d.to_string());
        }
    }
    // The multiarch directories glibc searches by default.
    for base in ["lib", "usr/lib"] {
        for ent in cx.dir(Path::new(base)) {
            let name = ent.name.to_string_lossy();
            if ent.is_dir && name.contains("-linux-") {
                let d = format!("{base}/{name}");
                if !dirs.iter().any(|s| *s == d) {
                    dirs.push(d);
                }
            }
        }
    }
    dirs
}

fn sorted(cx: &mut Ctx, dir: &Path) -> Vec<PathBuf> {
    let mut names: Vec<_> = cx.dir(dir).into_iter().filter(|e| !e.is_dir).map(|e| e.name).collect();
    names.sort();
    names.into_iter().map(|n| dir.join(n)).collect()
}

/// Sets a library target: absolute as given, relative resolved on the search
/// path, and unresolved marked so provenance leaves it alone.
fn target(cx: &mut Ctx, e: &mut Entry, lib: &str, libdirs: &[String]) {
    if lib.starts_with('/') {
        e.target_path = Some(PathBuf::from(lib));
        return;
    }
    for dir in libdirs {
        let cand = format!("{dir}/{lib}");
        if cx.root.exists(&cand) {
            e.target_path = Some(cx.root.abs(&cand));
            e.note("resolved_from", "loader search path");
            return;
        }
    }
    e.note("target_unverifiable", "a library found on the loader's search path");
}

fn entry(cx: &mut Ctx, rel: &Path, name: String, framework: &str, trigger: Trigger) -> Entry {
    let mut e = cx.entry(Kind::Plugin, rel, name);
    e.trigger = trigger;
    e.principal = None;
    e.enabled = Enablement::Enabled;
    e.note("loaded_by", framework);
    e
}

/// The gconv directory: the multiarch one on Debian, /usr/lib64 on Fedora.
/// A merged-usr host reaches one directory under two names; it is read once.
fn gconv_dirs(cx: &mut Ctx) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut push = |cx: &mut Ctx, d: PathBuf| {
        if let Ok(id) = cx.root.dir_identity(&d)
            && seen.insert(id)
        {
            out.push(d);
        }
    };
    for base in ["usr/lib", "lib"] {
        for ent in cx.dir(Path::new(base)) {
            if ent.is_dir && ent.name.to_string_lossy().contains("-linux-") {
                push(cx, Path::new(base).join(&ent.name).join("gconv"));
            }
        }
    }
    for d in ["usr/lib64/gconv", "usr/lib/gconv"] {
        push(cx, PathBuf::from(d));
    }
    out
}

fn gconv(cx: &mut Ctx, out: &mut Vec<Entry>) {
    let installed = cx.root.exists("usr/bin/iconv") || cx.root.exists("usr/lib/x86_64-linux-gnu/libc.so.6");
    for dir in gconv_dirs(cx) {
        let mut files = vec![dir.join("gconv-modules")];
        files.extend(sorted(cx, &dir.join("gconv-modules.d")).into_iter().filter(|f| f.to_string_lossy().ends_with(".conf")));
        for rel in files {
            let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
            for raw in bytes.split(|b| *b == b'\n') {
                let line = raw.split(|b| *b == b'#').next().unwrap_or_default().trim_ascii();
                let mut words = line.split(u8::is_ascii_whitespace).filter(|w| !w.is_empty());
                if words.next() != Some(b"module") {
                    continue;
                }
                let fields: Vec<&[u8]> = words.collect();
                // module <from> <to> <file> [cost]
                let (Some(from), Some(to), Some(file)) = (fields.first(), fields.get(1), fields.get(2)) else { continue };
                let mut file = String::from_utf8_lossy(file).into_owned();
                if !file.ends_with(".so") {
                    file.push_str(".so");
                }
                let display = file.trim_end_matches(".so");
                let mut e = entry(cx, &rel, format!("gconv:{display}"), "glibc gconv", Trigger::Always);
                e.note("conversion", format!("{} to {}", String::from_utf8_lossy(from), String::from_utf8_lossy(to)));
                if file.starts_with('/') {
                    e.target_path = Some(PathBuf::from(&file));
                } else {
                    let cand = dir.join(&file);
                    e.target_path = Some(cx.root.abs(&cand));
                }
                if !installed {
                    e.enabled = Enablement::Disabled;
                    e.note("not_run", "glibc gconv is not present");
                }
                out.push(e);
            }
        }
    }
}

fn p11_kit(cx: &mut Ctx, libdirs: &[String], out: &mut Vec<Entry>) {
    for dir in ["usr/share/p11-kit/modules", "etc/pkcs11/modules"] {
        for rel in sorted(cx, Path::new(dir)) {
            if !rel.to_string_lossy().ends_with(".module") {
                continue;
            }
            let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
            let module = String::from_utf8_lossy(&bytes).lines().find_map(|l| {
                let l = l.trim();
                l.strip_prefix("module:").map(|v| v.trim().to_string())
            });
            let Some(module) = module.filter(|m| !m.is_empty()) else { continue };
            let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let mut e = entry(cx, &rel, format!("p11-kit:{name}"), "p11-kit", Trigger::Always);
            target(cx, &mut e, &module, libdirs);
            out.push(e);
        }
    }
}

/// The value of a JSON string key, at any nesting: `"key" : "value"`.
fn json_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let at = text.find(&needle)?;
    let rest = text[at + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

fn icd_json(cx: &mut Ctx, dir: &Path, framework: &str, trigger: Trigger, libdirs: &[String], out: &mut Vec<Entry>) {
    for rel in sorted(cx, dir) {
        if !rel.to_string_lossy().ends_with(".json") {
            continue;
        }
        let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        let lib = json_string(&text, "library_path");
        let Some(lib) = lib.filter(|l| !l.is_empty()) else { continue };
        let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let layer = rel.parent().map(|p| p.ends_with("implicit_layer.d")).unwrap_or(false);
        let mut e = entry(cx, &rel, format!("{}:{name}", framework.to_lowercase()), framework, trigger);
        if layer {
            e.note("kind", "implicit layer, loaded into every Vulkan program");
        }
        // A JSON library_path relative to the manifest is relative to its
        // own directory, not the loader path (Vulkan loader rule); a bare
        // soname is searched.
        if !lib.starts_with('/') && (lib.contains('/') || lib.starts_with('.')) {
            let cand = dir.join(&lib);
            e.target_path = Some(cx.root.abs(&cand));
        } else {
            target(cx, &mut e, &lib, libdirs);
        }
        out.push(e);
    }
}

fn opencl(cx: &mut Ctx, libdirs: &[String], out: &mut Vec<Entry>) {
    for rel in sorted(cx, Path::new("etc/OpenCL/vendors")) {
        if !rel.to_string_lossy().ends_with(".icd") {
            continue;
        }
        let Some(bytes) = cx.read_capped(&rel, CAP) else { continue };
        let name = rel.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        for line in String::from_utf8_lossy(&bytes).lines() {
            let lib = line.trim();
            if lib.is_empty() {
                continue;
            }
            let mut e = entry(cx, &rel, format!("opencl:{name}"), "OpenCL", Trigger::Always);
            target(cx, &mut e, lib, libdirs);
            out.push(e);
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::Root;
    use crate::scan::{Options, Scan};

    fn put(dir: &Path, rel: &str, body: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn scan(dir: &Path) -> Scan {
        let root = Root::at(dir).unwrap();
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(Plugins)];
        crate::scan::run(&root, &Options { deep: false }, &collectors)
    }

    #[test]
    fn registries_name_the_library_each_framework_loads() {
        let d = std::env::temp_dir().join(format!("unbidden-plugins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        put(&d, "usr/bin/iconv", b"");
        // gconv, on Fedora's path.
        put(&d, "usr/lib64/gconv/gconv-modules", b"# c\nmodule\tINTERNAL\t\tEVIL//\t\tevil\t1\nalias X Y\n");
        put(&d, "usr/lib64/gconv/gconv-modules.d/extra.conf", b"module  FOO  BAR  /opt/abs.so  2\n");
        put(&d, "usr/lib64/gconv/evil.so", b"\x7fELF");
        // p11-kit.
        put(&d, "usr/share/p11-kit/modules/mymod.module", b"# x\nmodule: /usr/lib/mymod.so\npriority: 1\n");
        // A bare soname resolved on the search path.
        put(&d, "etc/pkcs11/modules/soname.module", b"module: bare.so\n");
        put(&d, "usr/lib/x86_64-linux-gnu/bare.so", b"\x7fELF");
        // EGL and a Vulkan implicit layer.
        put(&d, "usr/share/glvnd/egl_vendor.d/50_mesa.json", b"{ \"ICD\": { \"library_path\": \"libEGL_mesa.so.0\" } }");
        put(&d, "usr/share/vulkan/implicit_layer.d/beacon.json", b"{ \"layer\": { \"library_path\": \"/opt/layer.so\" } }");
        // OpenCL.
        put(&d, "etc/OpenCL/vendors/mesa.icd", b"/usr/lib/libMesaOpenCL.so.1\n");
        let s = scan(&d);
        let mut got: Vec<(&str, Option<&str>)> =
            s.entries.iter().map(|e| (e.name.as_str(), e.target_path.as_deref().map(|p| p.to_str().unwrap()))).collect();
        got.sort();
        assert_eq!(
            got,
            [
                ("egl:50_mesa.json", None),
                ("gconv:/opt/abs", Some("/opt/abs.so")),
                ("gconv:evil", Some(d.join("usr/lib64/gconv/evil.so").to_str().unwrap())),
                ("opencl:mesa.icd", Some("/usr/lib/libMesaOpenCL.so.1")),
                ("p11-kit:mymod.module", Some("/usr/lib/mymod.so")),
                ("p11-kit:soname.module", Some(d.join("usr/lib/x86_64-linux-gnu/bare.so").to_str().unwrap())),
                ("vulkan:beacon.json", Some("/opt/layer.so")),
            ]
        );
        let egl = s.entries.iter().find(|e| e.name.starts_with("egl:")).unwrap();
        assert!(egl.raw.contains_key("target_unverifiable"), "an soname EGL resolves via glvnd is left to the loader");
        let layer = s.entries.iter().find(|e| e.name == "vulkan:beacon.json").unwrap();
        assert!(layer.raw["kind"].contains("implicit layer"));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
