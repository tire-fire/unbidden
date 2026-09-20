unbidden — Design Specification v0.1
Sep 20, 2026
A Linux autostart and persistence enumerator. Rust, statically linked, read-only.
1. Purpose and scope
unbidden enumerates every mechanism by which code executes on a Linux host without a human invoking it, and reports what it finds as facts an analyst can act on.
It answers one question exhaustively: what runs here that nobody asked for right now? Boot, login, authentication, elapsed time, network state change, package installation, device attachment and shell startup are all in scope. The subject is the trigger, not the subsystem.
Audiences
Two, deliberately the same two Autoruns serves.
The incident responder has a host they suspect and a short window. Completeness matters most: a mechanism the tool does not know about is a mechanism the attacker keeps. They cannot trust the host itself, and they need output they can diff against a known-good baseline or hand to a colleague.
The system administrator has a machine behaving oddly and wants to know what starts on it. They need the noise gone. A desktop carries several hundred legitimate autostart entries, and a tool that lists all of them without ranking has told them nothing. They should not have to think about threat models to get value.
Both want the same data and a different default view. That is the central design fact, and §8 resolves it.
Scope boundary
v1 runs on a live local host, as root, and only reads. It does not modify, disable, remediate or write anything outside its own output files.
Supported platforms
Four distributions are supported targets. Correctness on these is a release requirement: a defect on any of them blocks a release, and every one is in CI.
Distribution
Versions
Package backend
Default desktop
Debian
12, 13
dpkg
— (server), GNOME
Ubuntu
22.04, 24.04 LTS
dpkg, plus snap
GNOME
Linux Mint
21.x, 22.x, and LMDE
dpkg
Cinnamon
Fedora
current and current-1
rpm, sqlite backend
GNOME
Everything else — RHEL, CentOS, Arch, openSUSE, Alpine — is best-effort. unbidden should run there and probably will, but nothing is tested and no defect blocks a release.
One thing this does not change: the musl static build target (§3, §12) stays, and is unrelated to whether Alpine is supported. Static linking is the ld.so.preload defence, not a packaging choice for musl-based distros.
The four-distro set is narrower than it looks in one respect and wider in another. Narrower: two package backends cover 100% of supported systems, and the rpm side reduces to sqlite alone (§7). Wider: Mint brings Cinnamon, and Ubuntu and Mint bring snap, both of which add work that a Debian-and-Fedora-only target would not have (§5, §7).
2. Non-goals
Each of these is excluded for a reason, not by oversight.
Not in v1
Why
Disabling or removing entries
Write access turns a read-only forensic tool into one that can brick a boot. Needs stable entry identity and a rollback story first. Revisit after the data model has settled.
Fleet agent or daemon mode
A resident process on every host is a different product with a different threat model. JSON output piped to whatever collects it covers the 80% case.
SIEM integration, alerting, scheduling
Downstream of stable JSON. Build the format, let others consume it.
Rootkit and LKM detection
A loaded kernel module that hides itself defeats userspace enumeration by construction. unbidden lists loaded modules as entries but makes no claim to detect hidden ones.
Offline image analysis
Deferred, not designed out. See §11.
Malware verdicts or hash reputation lookups
No network calls at all in v1. A DFIR tool that phones home from a compromised host is a liability. Hashes are emitted so the operator can look them up themselves.
Non-Linux targets
BSD and macOS share concepts but almost no paths.
On rootkits specifically
This limit is worth stating plainly in the README rather than burying it. If an attacker has kernel-level code execution, every syscall unbidden makes can lie to it. The tool is useful against the overwhelming majority of real persistence, which is userspace and file-backed, and it is honest about the ceiling.
3. Threat model and trust boundaries
The host may already be compromised. Every design decision below follows from that one assumption, and each has a matching persistence technique it defends against.
Static linking is a security control, not packaging convenience
/etc/ld.so.preload is a persistence mechanism. A dynamically linked scanner hands the attacker's shared object into its own address space before main() runs, at which point the scanner's open(), readdir() and stat() are all under attacker control. A statically linked binary never invokes ld.so and cannot be subverted this way.
This makes x86_64-unknown-linux-musl a requirement rather than a preference, and it means no crate that pulls in a C dependency requiring dynamic linkage can be accepted, however convenient.
Never shell out
rpm, dpkg, systemctl, crontab and ls are all binaries on the host being examined. Wrapping system binaries is a standard persistence technique, and a wrapper that filters its own entry out of the output is trivial to write. Anything unbidden learns by executing a host binary is worthless.
Every fact therefore comes from reading a file, a directory, or a kernel interface directly, or from a protocol spoken to a daemon over a socket. See §6 and §7 for the two places this is non-trivial.
Parsers face hostile input
Every file unbidden parses may have been authored by the adversary it is looking for: deliberately malformed .desktop files, crontab lines with embedded nulls, unit files with 10 MB ExecStart= values, symlink loops in ~/.config/autostart.
Consequences:
• Bound every read. No read_to_string on a path that an unprivileged user controls without a size cap.
• Never follow symlinks blindly when walking user-writable directories. Use openat with O_NOFOLLOW where the distinction matters, and record the link target as data rather than resolving through it.
• Treat all parsed content as opaque bytes until proven UTF-8. An ExecStart= line containing invalid UTF-8 is a finding, not a crash.
• A panic in one collector must not abort the scan. Collector failures are recorded as errors in the output and the run continues.
What the tool is not defended against
Kernel-level compromise (§2), a compromised build toolchain, and an operator running it from a mounted share on the suspect host. Document these rather than implying protection.
4. The Entry record
One struct, emitted by every collector. Everything downstream — flags, diff, TUI, JSON — reads only this. Getting it right now is what keeps offline support (§11) and a future rule engine from becoming rewrites.
Field
Type
Semantics
id
String
Stable synthetic identity. See below.
kind
enum
Which mechanism class: systemd_unit, systemd_timer, cron, xdg_autostart, shell_profile, pam, udev, rc_local, sysv_init, ssh_authorized_key, sudoers, ld_preload, kernel_module, pkg_hook, motd, network_dispatcher, dbus_service, systemd_generator, at_job, suid_binary, file_capability, git_hook
source
PathBuf
The file or directory the entry was read from. Always a real path on disk.
name
String
The entry's own name within that source: unit name, cron line index, .desktop filename.
command
Option<Vec<u8>>
The raw command or target, unparsed and un-decoded. None where the mechanism has no parseable command (a cron.daily script, a PAM module). Bytes, not String — hostile input may not be UTF-8.
target_path
Option<PathBuf>
The executable the command resolves to, where resolvable.
target_sha256
Option<String>
Hash of target_path, or of source where the entry is the script.
enabled
Enablement
Enabled, Disabled, Static, Masked, NotApplicable, Unknown. See §6.
trigger
enum
When it fires: Boot, Login, Auth, Schedule, DeviceEvent, NetworkEvent, PackageOp, Always. Lets a sysadmin ask "what runs at login" across mechanism classes.
principal
Option<String>
User the entry runs as, where determinable.
owner_uid / mode
u32
Ownership and permissions of source. A world-writable autostart file is itself a finding.
mtime
Option<SystemTime>
Modification time of source. Weak evidence — trivially forged — but clustering is informative.
provenance
Provenance
See §7.
flags
Vec<Flag>
Mechanical observations. See §8.
raw
Map
Collector-specific extras that do not generalise. Kept out of the typed surface deliberately.
Entry identity
id must be stable across runs for diff (§9) to mean anything, and must not change when the entry's content changes — otherwise a modified backdoor reads as "one removed, one added" instead of "one changed".
Rule: id is the full 256-bit blake3 of kind || source || name, hex-encoded. Content fields are excluded. A cron line's name is a position-independent hash of its schedule and command rather than its line number, so inserting a line above it does not re-identify everything below.
The first draft truncated this to 16 hex characters. That is wrong, and the arithmetic is worth recording so nobody re-proposes it.
64 bits is ample against accidents — a host carries a few thousand entries against a birthday bound near 2^32. The adversarial case is different. The attacker names the file, so they control part of the hash input. Finding a name colliding with any one of roughly 2,000 existing entry ids costs about 2^53 blake3 evaluations, which is days on a single GPU and hours on a rented cluster. Not comfortable for a value that decides whether two entries are the same entry.
The payoff for the attacker is a dropped row: if the diff or the renderer keys entries by id in a map, a collision silently overwrites one of them, and the one that vanishes can be theirs. Full width costs 24 bytes per entry in the JSON and removes the question entirely.
Two consequences:
• The human table and explain show a 12-character prefix and accept any unique prefix as an argument, the way git handles object ids. Truncation is a display concern, never a storage one.
• The diff detects duplicate ids and fails loudly rather than overwriting. That guard is worth having regardless of hash width, because it also catches collector bugs that emit the same entry twice.
On bytes vs strings
The command field being Vec<u8> rather than String will be irritating throughout the codebase. It is the right call: encoding-based evasion is cheap, and a scanner that silently lossy-converts an ExecStart= line has lost the evidence. JSON output emits it as a UTF-8 string where valid and as an escaped byte array where not, with a sibling boolean saying which.
5. Collector surface
A collector is a unit that walks one mechanism class and emits Entries. They are independent, run in parallel, and one failing does not stop the scan.
Collection is the first of three phases — collect, enrich, render (§14.4). Collectors emit facts about one mechanism class and nothing else; anything requiring knowledge of another collector's output belongs to enrichment.
Tier one — v1, non-negotiable
These cover what real intrusions actually use, and their absence would make the tool not worth running.
Collector
Source of truth
systemd units
/etc/systemd/system, /run/systemd/system, /usr/lib/systemd/system, /lib/systemd/system, plus /etc/systemd/user, /usr/lib/systemd/user and every user's ~/.config/systemd/user. .service, .timer, .socket, .path
cron
/etc/crontab, /etc/cron.d/*, /etc/cron.{hourly,daily,weekly,monthly}/*, /var/spool/cron/*, /var/spool/cron/crontabs/*, /etc/anacrontab
at jobs
/var/spool/cron/atjobs, /var/spool/at
XDG autostart
/etc/xdg/autostart, every /home/*/.config/autostart, /root/.config/autostart
shell profiles
/etc/profile, /etc/profile.d/*, /etc/bash.bashrc, /etc/zsh/*, and per-user .bashrc, .bash_profile, .bash_login, .profile, .zshrc, .zshenv
rc.local and SysV
/etc/rc.local, /etc/rc.d/rc.local, /etc/init.d/*, /etc/rc*.d/*
PAM
/etc/pam.d/* — pam_exec lines and modules resolving outside standard module directories
udev
/etc/udev/rules.d/*, /run/udev/rules.d/*, /lib/udev/rules.d/* — rules carrying RUN+=
ld.so preload
/etc/ld.so.preload, and LD_PRELOAD assignments found in the shell-profile and systemd collectors
SSH
every user's ~/.ssh/authorized_keys with command= directives, /etc/ssh/sshrc, /etc/ssh/sshd_config ForceCommand
Tier two — v1, fixed-path collectors
The original split was "if time allows", which is not a criterion. The real divide is cost class: a collector that reads a bounded set of known paths finishes in milliseconds, while one that must traverse the entire filesystem takes minutes and saturates the disk. Those are different products, not different priorities.
Everything below reads fixed paths and ships in v1. Three collectors from the first draft do not, and move to the --deep section that follows.
Sudoers is the one judgement call here. A correct parser must handle @includedir, #include, and user, host and command aliases. v1 ships a line-level scan for NOPASSWD and command specifications, follows includes one level, and marks its own output as line-level so nobody mistakes it for a resolved policy.
Collector
Source of truth
systemd generators
/etc/systemd/system-generators, /usr/lib/systemd/system-generators, user equivalents
package manager hooks
/etc/apt/apt.conf.d/*, /etc/dnf/plugins, /etc/yum/pluginconf.d, RPM transaction file triggers
MOTD
/etc/update-motd.d/*
NetworkManager
/etc/NetworkManager/dispatcher.d/*
D-Bus services
/usr/share/dbus-1/system-services, /etc/dbus-1/system.d
kernel modules
/etc/modules, /etc/modules-load.d/*, /etc/modprobe.d/* install lines, and /proc/modules for what is loaded
sudoers
/etc/sudoers, /etc/sudoers.d/* — NOPASSWD and command aliases
Tier three — behind --deep
These require walking the whole filesystem. On a host with a large /home or a build cache that is minutes of wall time and sustained disk I/O, so they are opt-in rather than default. An operator who wants them knows they want them.
Collector
Source of truth
Why deep
SUID and capabilities
SUID/SGID binaries outside package ownership, security.capability xattrs
No bounded path set; every mounted filesystem
git hooks
.git/hooks under discovered repositories, core.pager and core.editor in git configs
Repositories can be anywhere
Orphaned interpreters
Scripts referenced by entries but living outside any package
Only meaningful with a full walk
One traversal serves all three. Walk once, feed every deep collector from the same pass, and skip pseudo-filesystems, network mounts and anything crossing a device boundary unless told otherwise. Getting this wrong means a scan that hangs on an unresponsive NFS mount, which on an incident host is the worst possible failure.
--deep output is marked as such in the JSON header, and §9 treats a deep baseline and a shallow one as non-comparable for the same reason it rejects mismatched collector status.
Merged-usr deduplication
All four supported distributions ship merged /usr: /lib is a symlink to /usr/lib. So /lib/systemd/system and /usr/lib/systemd/system are the same directory, and the systemd search path in the tier-one table lists both.
A naive walk therefore reports every vendor unit twice. Worse, the duplicates carry different source paths and so different entry ids (§4), making them two distinct entries that never reconcile in a diff.
Rule: resolve each search-path root to its device and inode before walking, walk each distinct inode once, and record the canonical path. This is correctness rather than optimisation, and it needs a test on each supported distro so that a future non-merged system still works.
Desktop environment mechanisms
Mint's Cinnamon is why this subsection exists. XDG autostart covers most desktop persistence, but Cinnamon additionally loads JavaScript applets, desklets and extensions into the session process at login, from ~/.local/share/cinnamon/applets, desklets, extensions and their /usr/share/cinnamon counterparts. Which ones are enabled lives in dconf under the Cinnamon schema, not in their presence on disk.
This is a real autostart mechanism that no existing Linux tool enumerates, and Mint being a supported target makes it tier one rather than a curiosity. GNOME Shell extensions (~/.local/share/gnome-shell/extensions) have the same shape and cover the other three distributions' default desktops, so this is one collector with two backends.
Reading enablement means parsing dconf's binary database directly, since shelling out to gsettings or dconf is barred by §3. The dconf_rs crate is not an option despite its download count — it invokes Command::new("dconf").
Resolved: the gvdb crate (v0.10.1, actively maintained) reads the glib gvdb format in pure Rust. Its default feature set pulls only zerocopy, serde and zgvariant; the glib C binding is an optional feature and stays off. The same crate also reads /usr/share/glib-2.0/schemas/gschemas.compiled, which is the other half of the answer — the user database only contains keys the user has changed, so schema defaults are needed to know what is enabled on an untouched account.
Three caveats:
• dconf is layered. /etc/dconf/profile/user names the database stack, system databases live in /etc/dconf/db, and locks can pin a key. Full resolution means reading the profile and walking the stack, not just the user file.
• The gvdb crate is written for GResource. Reading the dconf hash-table variant needs verifying against a real ~/.config/dconf/user early, before this is committed to tier one.
• zgvariant has very few downloads. Same bus-factor note as rpmdb (§7): be ready to vendor.
Deferred
GRUB and initramfs (pre-OS, needs image parsing), container runtimes, web shells (requires content heuristics, out of scope for a mechanical tool), Polkit rules, X11 ~/.xinitrc and ~/.xprofile.
The user-enumeration problem
Several collectors are per-user. With CGO-free static linking there is no NSS, so accounts come from parsing /etc/passwd directly. That misses LDAP and SSSD accounts.
Decision: enumerate the union of /etc/passwd entries, directories present under /home, /root, and any directory appearing as a home in a discovered crontab spool. Record the discovery source per user. Document the LDAP gap explicitly rather than silently under-reporting.
6. Enablement resolution
A unit file sitting in /etc/systemd/system may do nothing. A unit enabled through a .wants/ symlink will not appear in a naive directory walk as enabled. Conflating presence with enablement is the single most common defect in existing Linux autostart tools, and avoiding it is a large part of unbidden's value.
Live host: D-Bus
Talk to org.freedesktop.systemd1 on /run/systemd/private or the system bus, calling ListUnitFiles and ListUnits on org.freedesktop.systemd1.Manager. This gives authoritative UnitFileState (enabled, disabled, static, masked, linked, generated, transient) and the runtime ActiveState and SubState.
zbus speaks the wire protocol in pure Rust with no libdbus, which keeps the static-linking requirement intact.
Notes:
• Query the system manager and each user manager. User units live in a per-user bus that may not be running; absence of a user manager is not absence of user units, so the filesystem walk still reports the unit with enabled: Unknown.
• generated is significant: a generated unit came from a systemd generator, which is itself a persistence mechanism (§5, tier two). Cross-reference these.
• D-Bus gives state for units systemd knows about. A unit file present on disk that systemd has not loaded still needs reporting, so the filesystem walk is the primary enumeration and D-Bus is the enrichment, never the reverse.
Fallback
Where D-Bus is unreachable — systemd not running, socket permissions, a container without a manager — fall back to resolving .wants/ and .requires/ symlinks across the unit search path and mark enabled accordingly, with a DegradedEnablement flag on the entry so the operator knows the answer is inferred.
This fallback is also the offline-root implementation (§11), which is a reason to build it in v1 even though D-Bus normally answers.
Precedence
The unit search path is ordered: /etc/systemd/system shadows /run/systemd/system shadows /usr/lib/systemd/system. An admin-placed unit in /etc overriding a vendor unit of the same name is worth surfacing explicitly — it is both a legitimate admin action and a persistence technique. Emit both entries, flag the shadowed one.
7. Provenance
This is the feature that makes unbidden worth building rather than another path-lister. It is the Linux answer to Autoruns' code-signature verification, and arguably a stronger signal.
Windows asks: is this binary signed, and by whom? Linux has no signature on arbitrary files, but it has something better — a per-file record of which package shipped it and what its contents were at install time. That turns "is this file supposed to be here?" from a judgement call into a lookup.
The verdict
For source and for target_path, resolve one of:
Verdict
Meaning
Packaged { package, version, intact: true }
Owned by an installed package and its hash matches the package manifest. Almost always uninteresting.
Packaged { package, version, intact: false }
Owned by a package but the contents have changed since install. High signal. This is a trojaned system binary or an edited unit file.
Unpackaged
No package claims this file. Normal for admin-authored config, and exactly where attacker-authored persistence lives.
Unknown
No package database found, or the file is on a filesystem the database does not cover.
Implementation
Read the databases directly. Never invoke rpm or dpkg (§3).
The supported platform set (§1) reduces this to exactly two backends, and simplifies the harder one considerably.
dpkg is straightforward: /var/lib/dpkg/status for installed packages, /var/lib/dpkg/info/*.list for file ownership, and /var/lib/dpkg/info/*.md5sums for integrity. All plain text. Build a path-to-package index once at startup.
Two dpkg-specific hazards, both of which would otherwise produce false PackagedModified findings at scale:
Conffiles. Configuration files are expected to differ from what the package shipped — that is what a conffile is for. dpkg records their original digests separately, in the Conffiles: field of /var/lib/dpkg/status, and checksum verification tools exclude them by default. unbidden must do the same: a conffile whose contents differ is Packaged and intact-by-policy, carrying a distinct ConffileModified marker rather than the high-signal PackagedModified flag. Without this, every host with an edited /etc/ssh/sshd_config lights up.
Missing md5sums. Not every package ships a .md5sums file. Where none exists, integrity is genuinely unknown and must be reported as Packaged with integrity Unknown, never as intact. Silently treating absent checksums as passing is how a scanner gives false assurance about exactly the file an attacker replaced.
rpm is the hard part. The database backend varies by RPM version: BerkeleyDB (Packages) on RHEL 7 and 8-era systems, ndb, or SQLite (rpmdb.sqlite) on RPM 4.16 and later. All three must be handled to cover the distro matrix.
With Fedora as the only supported rpm distribution, that reduces to sqlite alone. Fedora 33 changed the default rpmdb backend to sqlite, and BDB dropped to read-only support in Fedora 34, so no supported Fedora release carries a BDB database. bdb and ndb come free with the rpmdb crate and should stay enabled, but no release is gated on them and they are not in CI. The corollary is that the rusqlite bundled-feature decision below is not an edge case — it is the entire rpm path.
Snap, and the limits of package provenance
Ubuntu and Mint ship snapd, which installs systemd units named snap.*.service along with mount units for each squashfs revision. dpkg owns none of these files. Under the §7 rules as written, every snap on the system reports Unpackaged — the same verdict an attacker's unit gets.
This is the largest false-positive source in the supported set, and it matters because Unpackaged is the flag the tool leads with. Options, in order of preference:
1. Read snapd's own state (/var/lib/snapd/state.json, and the /snap/<name>/<rev> layout) as a third provenance source, giving Packaged with a snap origin.
2. Treat units matching snapd's generated-unit naming convention as GeneratedBy(snapd), a distinct provenance verdict that is neither packaged nor unpackaged.
Option 1 is more work and correct; option 2 is cheap and covers most of the noise. Start with 2, and note that the same GeneratedBy verdict also handles cloud-init on Ubuntu server images and systemd generators generally (§6), so it is machinery worth having regardless.
Resolved (spike, 20 Sep 2026). The crate rpmdb (github.com/yybit/rpmdb-rs, MIT, v0.1.1) is a direct port of go-rpmdb and reads all three backends — bdb, ndb and sqlite3 — auto-detecting the format from the file. Its Package struct exposes base_names, dir_indexes and dir_names, which reconstruct the full owned-file list. Path-to-package ownership therefore works off the shelf.
File integrity does not. RPMTAG_FILEDIGESTS (1035), FILEMODES, FILESIZES and FILEFLAGS are all defined in the crate's tag table but none are parsed into Package, and RPMTAG_FILEDIGESTALGO (5011) is absent entirely. The header parser already works, so this is adding match arms to one function, not a port. Contribute upstream, and vendor the patch until it lands.
Two risks to carry:
• Static linking. The crate depends on rusqlite with default features, which links the system libsqlite3 dynamically and would break §3. Fix: declare rusqlite with the bundled feature in unbidden's own manifest so Cargo's feature unification applies it to the transitive dependency, compiling SQLite from source into the binary. Statically linked C is acceptable; dynamic linkage is not. The CI ldd check (§12) is what proves this holds.
• Bus factor. v0.1.1, single maintainer, ~2,000 downloads. Vendor it, or be prepared to fork. The format handling is a few hundred lines and go-rpmdb remains the reference.
Note that RPM stores per-file digests in the header, so integrity checking is available without the rpm -V binary; the digest algorithm varies by package and must be read from RPMTAG_FILEDIGESTALGO.
Cost
Building the full path index is the most expensive part of a scan. Do it once, lazily, and only if at least one collector produced entries needing resolution.
8. Opinionation model
Decision: mechanical flags and noise suppression, no risk scores, no rule engine in v1. This mirrors Autoruns, and the reasoning is worth recording because it will be challenged.
What Autoruns actually does
Autoruns is an enumerator, not a detector. It computes no risk score and makes no claim that any entry is malicious. Its entire opinionated surface is four mechanisms:
1. Hide Microsoft/Windows Entries — a filter on signature publisher, not on badness. This is the feature that takes an unreadable list of roughly 800 entries down to about 30. It is noise suppression, and it is arguably the single most valuable thing the tool does.
2. Verify Code Signatures — highlights entries whose backing file is unsigned or fails verification. Mechanical and checkable, not a heuristic.
3. Orphan highlighting — entries pointing at files that no longer exist, shown in a different colour.
4. VirusTotal lookup — an outsourced verdict, explicitly someone else's opinion, shown as a detection ratio rather than folded into a score.
Nothing in that list says "this is suspicious because it looks unusual." The analyst decides. The tool's job is completeness, plus a small number of facts that are cheap to verify and expensive to fake.
unbidden's equivalents
Autoruns
unbidden
Hide Microsoft entries
Hide entries that are Packaged and intact — default on. This is the sysadmin's view and the IR triage starting point.
Unsigned / unverified
Unpackaged and PackagedModified flags (§7)
Orphan entry
TargetMissing — the entry's command resolves to a path that does not exist
VirusTotal
Nothing in v1. Hashes are emitted; lookups are the operator's business (§2)
The flag set
Every flag must be mechanically derivable and defensible in one sentence. No flag may be a guess.
• Unpackaged — no package owns the backing file
• PackagedModified — package owns it, contents differ from the manifest digest
• TargetMissing — command resolves to a non-existent path
• TargetUnresolvable — command could not be parsed into a path at all
• WorldWritable — source file or its parent directory is writable by anyone
• OwnerMismatch — a file under a user's home is owned by a different user
• HiddenPath — component of the path is dot-prefixed, or lives under /tmp, /dev/shm, /var/tmp
• NonStandardLocation — a unit or module outside the standard search path for its kind
• ShadowsVendorUnit — overrides a same-named unit earlier in the search path (§6)
• DegradedEnablement — enablement inferred rather than authoritative (§6)
• EncodingAnomaly — command contains non-UTF-8 bytes, or base64/hex-looking payloads over a length threshold
EncodingAnomaly is the closest thing to a heuristic here and is deliberately narrow: it reports an observable property of the bytes, not an inference about intent.
Why no scoring
A 0-to-100 risk number would have to be invented, could not be justified per-entry, and trains operators to filter on it and miss everything below the cut. The flags compose into filters that the operator controls (--flag unpackaged --flag world-writable), which is the same power with none of the false authority.
A rule engine remains possible later precisely because the Entry record (§4) carries the raw facts. Nothing here forecloses it.
Suppression is a rendering behaviour, not a scan behaviour: --json always emits every entry, and the human table always states how many it hid. See §14.3.
Flags requiring cross-entry knowledge — ShadowsVendorUnit, and LD_PRELOAD assignments found in any collector's output — are applied by the enrichment pass described in §14.4, not by collectors.
9. Baseline and diff
Noise is the problem that kills tools in this category.
Provenance filtering (§8) handles most of it; diffing handles the rest, and is what makes unbidden useful as a periodic control rather than only a one-shot.
Model
A scan with --save writes a snapshot. A scan with --against emits the same Entry stream annotated with a delta: Added, Removed, Changed with the names of the changed fields, or Unchanged.
Entry identity (§4) is what makes Changed meaningful rather than a churn of add/remove pairs. A backdoor that rewrites its own ExecStart line shows up as one changed entry naming command and target_sha256.
Snapshot format
The snapshot is the JSON output of §10, unmodified, plus a header recording hostname, kernel version, distro, scan time, unbidden version, and which collectors ran and which failed.
That last part matters. A baseline taken when the rpm collector errored is not comparable to one where it succeeded, and the diff must say so rather than reporting every RPM-owned entry as newly appeared.
Expected workflow
• Sysadmin: baseline a known-good machine of a given role, compare its fleet-mates by hand.
• IR: baseline a clean image of the same build, compare the suspect host.
• Either: baseline before a change window, compare after.
This is the pattern MITRE CAR-2013-01-002 describes for Autoruns, periodic collection and comparison for differences, and it transfers directly.
10. Interfaces
CLI
Subcommands: scan, explain <entry-id>, tui.
Scan flags: --all to disable suppression, --json for the record stream, --kind and --trigger and --flag as filters, --save <path> to write a baseline, --against <path> to compare with one.
Defaults matter more than options here. Bare unbidden with no arguments serves the sysadmin: suppressed, readable, sorted by kind. --all --json serves the responder. Neither audience should have to read the manual to get their view.
explain dumps everything known about a single entry including the raw source text it was parsed from, which is what an analyst actually wants after spotting a row.
JSON
Newline-delimited, one Entry per line, so output streams and survives truncation. A pretty array form for humans reading it directly.
The schema is a compatibility contract from 0.1 onward: additive changes only, version recorded in the header. This is the primary interface — the TUI and the human table are views over it, and any fact visible in either must be present here.
TUI
ratatui. Kinds on the left, entry list centre, detail pane right. Filter by flag, toggle suppression, mark entries reviewed, view the backing file.
Explicitly a v1.1 target. The CLI and JSON have to be right first: a TUI built early risks bending the record shape to fit the widget rather than the reverse.
11. Designing for offline roots
Decision from scoping: live host only in v1, but nothing may foreclose offline analysis of a mounted image or chroot. Retrofitting this later means touching every collector, so the constraints go in now.
The Root abstraction
No collector may name an absolute path directly. All filesystem access goes through a Root handle that resolves paths relative to a scan root, defaulting to /.
In practice: root.open("etc/systemd/system"), never File::open("/etc/systemd/system"). A lint or a #[deny]-style convention should enforce this, because one collector reaching for an absolute path silently breaks offline mode for everyone.
Root also owns the symlink policy from §3. An offline root makes this urgent rather than theoretical: a symlink inside a mounted image pointing at /etc/passwd resolves to the analyst's /etc/passwd, not the image's. Every resolution must be confined to the root, which means openat2 with RESOLVE_IN_ROOT where the kernel supports it and manual path confinement where it does not.
What offline costs
Two capabilities do not survive:
D-Bus enablement (§6). There is no running systemd in a mounted image. This is why the symlink-resolution fallback is a v1 deliverable rather than a contingency — it is the offline implementation, tested continuously on live hosts where its answers can be checked against D-Bus. That validation loop is only available while both paths exist.
Live-only facts. Loaded kernel modules, running processes, and current mounts are absent. The affected collectors must degrade to their on-disk sources and mark the entry rather than omitting it.
Rules for v1
1. Every path goes through Root.
2. The symlink-resolution enablement path ships in v1 and is tested against D-Bus for agreement.
3. Any collector reading a live-only interface declares it, so the offline mode knows what to skip.
4. Distro and version detection reads from the root (/etc/os-release), never from the running system.
12. Build and dependencies
Target
x86_64-unknown-linux-musl and aarch64-unknown-linux-musl, fully static. Verified in CI: the build fails if ldd reports the binary as dynamically linked, because a regression here is a silent loss of the §3 guarantee rather than a visible break.
Static musl means the binary runs on RHEL 7's glibc 2.17 and on Alpine without modification. That reach is the point.
Crate constraints
No dependency may require dynamic linkage or a C library at runtime. Candidates:
Need
Crate
Note
D-Bus
zbus
Pure Rust, no libdbus
Syscalls, xattrs
rustix or nix
rustix preferred, it can avoid libc entirely
Hashing
sha2, blake3
blake3 for entry ids, sha2 for reported digests
CLI
clap

JSON
serde_json

TUI (v1.1)
ratatui

RPM database
rpmdb (vendored, patched)
All three backends; needs a digest patch, see §7
SQLite (for rpmdb)
rusqlite, bundled feature
Compiles SQLite from C source, statically linked
dpkg
hand-rolled
Plain text, not worth a dependency
Binary constraints
Single binary, no config file required, no runtime data files. Anything it needs to know about paths and mechanisms is compiled in. The operator copies one file to a host and runs it.
Size is not a concern but should be watched — a 50 MB binary is awkward to move onto a host over a constrained channel.
13. Testing
PANIX as ground truth
PANIX (github.com/Aegrah/PANIX) is a Linux persistence framework that installs roughly 38 mechanisms, each with a paired revert script and a MITRE ATT&CK mapping. It is an offensive tool and contains no enumeration code, so it is not a dependency — it is the test fixture.
The loop, per mechanism, in a disposable VM:
1. Snapshot baseline with unbidden.
2. Plant the mechanism with PANIX.
3. Scan. Assert the entry appears, with the expected kind, source, command and flags.
4. Revert with PANIX.
5. Scan. Assert the diff is clean against the baseline.
Step 5 is as valuable as step 3: it catches collectors that report stale or phantom entries, which is how a tool loses an operator's trust permanently.
This gives real adversary-shaped fixtures rather than hand-written ones, and PANIX's mechanism list doubles as the coverage matrix for §5. A mechanism PANIX implements that unbidden does not detect is a tracked gap with a name and a technique ID.
Distro matrix
The four supported distributions from §1, all in CI, all gating release: Debian 12 and 13, Ubuntu 22.04 and 24.04, Linux Mint 21.x and 22.x plus LMDE, and Fedora current and current-1.
The PANIX loop above runs against every one of them. That is the point of automating it — thirty-eight mechanisms across nine images is not a matrix anyone verifies by hand, and the distro-specific defects are exactly the ones that hide.
Desktop coverage needs care. Mint gets a Cinnamon image; Ubuntu and Fedora bring GNOME. Both desktops matter for the extension collector (§5), and a headless image will silently skip it, so at least one image per desktop must boot a session.
Specific things to assert per distro, because they are the ones a generic test misses:
• Merged-usr: vendor units appear exactly once, on all four (§5).
• Fedora: the rpm path exercises sqlite; SELinux enforcing does not block collection; file digests read correctly given RPMTAG_FILEDIGESTALGO.
• Debian family: an edited conffile does not raise PackagedModified; a package with no .md5sums reports integrity Unknown rather than intact (§7).
• Ubuntu and Mint: installed snaps do not flood the output as Unpackaged (§7).
• LMDE: confirm the Debian base is detected as such, not as Ubuntu, since /etc/os-release differs from mainline Mint.
RHEL, CentOS, Arch, openSUSE and Alpine are not tested. Community bug reports welcome; no release waits on them.
Parser fuzzing
Every parser gets a cargo-fuzz target. §3 establishes that parser input is adversarial; fuzzing is how that stops being an aspiration. Priority order: unit files, crontabs, .desktop files, udev rules, PAM configs.
Golden files
Collector output for a fixed synthetic filesystem tree, checked into the repository. Catches unintended changes to the Entry record, which is the schema contract of §10.
14. Resolved decisions
All seven questions from the first draft are now answered. Two smaller ones opened in their place and are listed at the end.
1. RPM database access — resolved
See §7. rpmdb covers all three backends; file ownership works today, integrity needs a small upstream patch. Not a blocker, and the spike is done.
2. Raw source text in explain — yes, and it changes the command's shape
explain includes the source text by default; scan never does, at any verbosity. The distinction is consent: explain <id> is a deliberate request for one entry, while scan --json output gets pasted into tickets and chat.
--no-source suppresses it. Excerpts are capped — the whole file under 64 KB, otherwise the matching region plus twenty lines either side.
One consequence worth building in deliberately: explain re-reads the file rather than replaying what the scan captured, and reports when the current hash differs from the one the scan recorded. On a live compromised host, an entry that changed between scan and inspection is itself a finding.
3. Suppression default — suppression is presentation, never data
The root cause of this question is a category error in the first draft: suppression was specified as a scan behaviour when it is a rendering behaviour. Fixing that removes the risk entirely.
Three rules:
1. --json implies --all. Machine output is always complete; filtering is the consumer's job. A responder cannot miss an entry they were never shown, because the JSON always shows everything.
2. The human table suppresses by default and always prints a trailer naming the count: 142 entries hidden (packaged, intact) — use --all. Never silent.
3. Suppression tests Packaged AND intact. A PackagedModified entry is never suppressed. This is the highest-signal finding the tool produces and it lives inside the category being hidden, so it gets an explicit test case, not just a sentence here.
4. LD_PRELOAD correlation — add an enrichment phase
The question was framed as "how far to chase LD_PRELOAD", but the real issue is that some facts are inherently relational and the pipeline had nowhere to put them. ShadowsVendorUnit (§6) has the same problem and was already specified without a home.
Resolution: three phases, not two.
1. Collect. Collectors stay independent, know nothing of each other, run in parallel, emit Entries.
2. Enrich. A pass over the assembled Entry set adds flags that require cross-entry knowledge: LD_PRELOAD assignments found in any collector's captured environment, unit shadowing, a cron job whose target is also an unpackaged SUID binary.
3. Render. Suppression, filtering, output.
So yes, chase LD_PRELOAD everywhere — unit Environment= and EnvironmentFile=, shell profiles, PAM pam_env configs, /etc/environment — because collector independence is preserved. Each collector records environment assignments it encounters as ordinary Entry data; the enrichment pass interprets them.
This phase is where a rule engine would eventually live (§8), which is a second reason to establish it now.
5. Name and namespace — decided
The repository lives under a personal GitHub account as unbidden. No organisation. GitHub redirects on transfer, so moving it to an org later costs no broken links or stale clone URLs.
Verified free on 20 Sep 2026: crates.io, PyPI, npm, and Ubuntu 24.04 main and universe. The dormant GitHub org named unbidden is irrelevant under this decision.
Action: reserve the crates.io name now with a stub carrying a real README stating intent, and follow it with code reasonably soon — crates.io policy targets squatting, not placeholders with a plan.
6. Licence — MIT, decided
MIT. Permissive, so the tools most likely to embed unbidden can: Velociraptor (Apache-2.0), osquery (Apache-2.0 or GPLv2), Wazuh (GPLv2), and commercial IR vendors, which are most of the market. A copyleft licence would block exactly the adoption that makes broad mechanism coverage worth maintaining.
MIT also matches rpmdb, the one dependency being vendored and patched (§7), which keeps the vendored-code situation simple.
Two consequences accepted deliberately:
• No patent grant. The Rust convention is Apache-2.0 OR MIT because Apache-2.0 adds an express patent licence and a retaliation clause. MIT has neither. Low risk for a tool that reads files and parses formats, but it is a real difference rather than a stylistic one, and worth revisiting if the project starts taking corporate contributions.
• A vendor can fork and close it. For a project whose value is breadth of coverage rather than a defensible core, reach is worth more than reciprocity.
7. Non-root behaviour — degrade, and make it structural
Run degraded, never refuse. But a warning banner is not enough, because partial output that looks complete is worse than no output.
Collector status is already part of the snapshot header (§9). Extend it: each collector reports Complete, or Partial with the list of paths it could not read. The human table prints a banner, the JSON header carries the detail, and — the part that matters — a baseline taken non-root refuses to diff against one taken as root. §9 already requires the diff to reject mismatched collector status, so this needs no new machinery, only a test.
8. Collector scope — resolved by cost class, not time
"Tier two if time allows" was not a criterion. §5 now splits collectors by cost: fixed-path collectors all ship in v1, and the three that need a full filesystem traversal move behind --deep as tier three. Sudoers ships as a line-level scan, labelled as such.
9. Entry id width — resolved, full 256 bits
Truncating to 64 bits was wrong. §4 carries the arithmetic: a targeted collision against a host's entry set costs roughly 2^53, and the payoff is a silently dropped row. Store the full hash, display a 12-character prefix, resolve unique prefixes on input.
10. dconf reading — resolved
The gvdb crate reads the format in pure Rust with default features. §5 has the detail and the three caveats. The extension and applet collector stays tier one.
Nothing outstanding
Every question raised so far is closed. The next unknowns will come from contact with real systems rather than from reasoning, and the ones most likely to bite are named in §13: the rpmdb crate against a genuine Fedora sqlite database, and gvdb against a genuine ~/.config/dconf/user. Both are worth an afternoon before any collector is written.
