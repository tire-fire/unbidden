unbidden — Design Specification v0.2
Sep 22, 2026. v0.2 brings the spec into line with v0.1.0 as built and with the fixes and test work that followed it; §15 lists what changed and what is still open.
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
• A path under a home directory is read only if, once every link along it is followed, it still lies inside that home. Otherwise ~/.bashrc -> /etc/shadow makes the scanner an exfiltration channel: the account that wrote the link need not be able to read the target, but the scanner can, and prints it. The whole chain is resolved, not the first hop — ../../etc/shadow, a link to a second link, and a linked directory partway down the path all leave the home. The resolved path is then opened with every link refused, so a swap between check and open fails rather than escapes. The link is recorded on the entry as not followed.
• Content an unprivileged user controls must never make a collector Partial. A capped read, a refused home link, a malformed ~/.config/dconf/user are properties of what is on disk and the same on every run; they are reported in the collector's status as limited reads, not as unreadable paths. Otherwise any account could make every later --against refuse to run (§9).
• Text from the scanned disk is never written raw to a terminal. Control characters, bidi overrides and zero-width characters in a command, a file name or a source line are shown as escapes, since their presence is evidence. ESC[2K ESC[1A in a crontab line would otherwise erase the table row that reports it.
• Treat all parsed content as opaque bytes until proven UTF-8. An ExecStart= line containing invalid UTF-8 is a finding, not a crash.
• A panic in one collector must not abort the scan. Collector failures are recorded as errors in the output and the run continues. The same holds for the enrichment pass (§14.4), which parses the package databases and follows interpreter lines: each stage is isolated, entry-by-entry where it works per entry, and a failure is recorded in the header's enrichment_failures. A package backend that panics leaves the paths it might have owned Unknown, never Unpackaged.
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
Which mechanism class: systemd_unit, systemd_timer, cron, xdg_autostart, shell_profile, pam, udev, rc_local, sysv_init, ssh_authorized_key, sudoers, ld_preload, kernel_module, pkg_hook, motd, network_dispatcher, dbus_service, systemd_generator, at_job, desktop_extension, suid_binary, file_capability, git_hook
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
Rule: id is the full 256-bit blake3 of kind || source || name, each part length-framed so no two splits of the input collide, hex-encoded. source is the path within the scan root, so a host scanned live and the same host mounted as an image give the same ids. Content fields are excluded. A cron line's name is a position-independent hash of its schedule and command rather than its line number, so inserting a line above it does not re-identify everything below.
The cost of that rule, accepted: a cron line has no name of its own, so its command is part of its identity, and editing a cron job's command reads in a diff as one removed and one added rather than one changed. Keying on the schedule alone would make two jobs with the same schedule in one file the same entry, which the duplicate-id guard below would then refuse.
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
The whole unit search path systemd.unit(5) gives, in its order: /etc/systemd/system.control, /run/systemd/system.control, /run/systemd/transient, /run/systemd/generator.early, /etc/systemd/system, /etc/systemd/system.attached, /run/systemd/system, /run/systemd/system.attached, /run/systemd/generator, /usr/local/lib/systemd/system, /usr/lib/systemd/system, /run/systemd/generator.late. For user managers: /etc/xdg/systemd/user, /etc/systemd/user, /run/systemd/user, /usr/local/share and /usr/share/systemd/user, /usr/local/lib and /usr/lib/systemd/user, and in every home ~/.config/systemd/user.control, ~/.config/systemd/user and ~/.local/share/systemd/user. .service, .timer, .socket, .path, and their drop-ins
cron
/etc/crontab, /etc/cron.d/*, /etc/cron.{hourly,daily,weekly,monthly}/*, /var/spool/cron/*, /var/spool/cron/crontabs/*, /etc/anacrontab
at jobs
/var/spool/cron/atjobs, /var/spool/at
XDG autostart
/etc/xdg/autostart, each session's /etc/xdg/xdg-*/autostart, every /home/*/.config/autostart, /root/.config/autostart
shell profiles
/etc/profile, /etc/profile.d/*, /etc/bash.bashrc, /etc/zsh/*, and per-user .bashrc, .bash_profile, .bash_login, .profile, .zshrc, .zshenv; and the environment files that set variables for every session: /etc/environment, /etc/security/pam_env.conf, and the systemd environment.d drop-ins, per-user ~/.config/environment.d included
rc.local and SysV
/etc/rc.local, /etc/rc.d/rc.local, /etc/init.d/*, /etc/rc*.d/*
PAM
/etc/pam.d/*, and /usr/lib/pam.d/* for a service /etc/pam.d does not name — pam_exec lines and modules resolving outside standard module directories
udev
/etc/udev/rules.d/*, /run/udev/rules.d/*, /usr/local/lib/udev/rules.d/*, /lib/udev/rules.d/* — rules carrying RUN+=
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
Every directory systemd.generator(7) lists: /run, /etc, /usr/local/lib and /usr/lib/systemd/system-generators, and the user-generators equivalents
package manager hooks
/etc/apt/apt.conf.d/*, /etc/dnf/plugins, /etc/yum/pluginconf.d, RPM transaction file triggers
MOTD
/etc/update-motd.d/*
NetworkManager
/etc/NetworkManager/dispatcher.d/*
D-Bus services
The system and session services directories under /usr/share, /usr/local/share, /usr/lib, /run and /etc; the policy files in the system.d and session.d directories beside them are read to annotate the service each one names
kernel modules
/etc/modules, modules-load.d/* and modprobe.d/* install lines under /etc, /run, /usr/local/lib and /usr/lib, and /proc/modules for what is loaded
sudoers
/etc/sudoers, /etc/sudoers.d/* — NOPASSWD and command aliases
Tier three — behind --deep
These require walking the whole filesystem. On a host with a large /home or a build cache that is minutes of wall time and sustained disk I/O, so they are opt-in rather than default. An operator who wants them knows they want them.
Collector
Source of truth
Why deep
SUID and capabilities
SUID/SGID binaries, security.capability xattrs; enrichment flags the ones no package owns
No bounded path set; every mounted filesystem
git hooks
.git/hooks under discovered repositories, core.pager and core.editor in git configs
Repositories can be anywhere
Orphaned interpreters
Scripts referenced by entries but living outside any package
Only meaningful with a full walk
As built, the third is not a --deep collector. "Referenced by entries" is a relation between entries, which §14.4 puts in enrichment, and nothing in it needs a traversal: every file it reads was already named by an entry. So enrichment reads each script an entry runs, follows its interpreter line and any file it hands control to, and emits those as entries with their own provenance. One hop only, and only for paths written out in full; nothing is guessed at or recursed into.
One traversal serves the other two. Walk once, feed every deep collector from the same pass, and skip pseudo-filesystems, network mounts and anything crossing a device boundary unless told otherwise. Getting this wrong means a scan that hangs on an unresponsive NFS mount, which on an incident host is the worst possible failure.
--deep output is marked as such in the JSON header, and §9 treats a deep baseline and a shallow one as non-comparable for the same reason it rejects mismatched collector status.
Merged-usr deduplication
All four supported distributions ship merged /usr: /lib is a symlink to /usr/lib. So /lib/systemd/system and /usr/lib/systemd/system are the same directory, and the systemd search path in the tier-one table lists both.
A naive walk therefore reports every vendor unit twice. Worse, the duplicates carry different source paths and so different entry ids (§4), making them two distinct entries that never reconcile in a diff.
Rule: resolve each search-path root to its device and inode before walking, walk each distinct inode once, and record the canonical path. This is correctness rather than optimisation, and it needs a test on each supported distro so that a future non-merged system still works.
It holds for every collector with a list of search directories, not only systemd: udev rules, modprobe and modules-load drop-ins, NetworkManager dispatchers, D-Bus services and environment.d all have a /lib and a /usr/lib spelling. A search directory that is itself a link — Debian ships /etc/xdg/systemd/user -> /etc/systemd/user — is walked under the path it resolves to.
The canonical path has to be used on the other side of every lookup too. systemd on Debian 12, Ubuntu 22.04 and Mint 21 names its vendor units under /lib/systemd/system, and a package database may record either spelling. Both lookups (§6, §7) resolve the directory part of the path they are asked about before matching.
The CI test does not compare entry ids, which include the path and so differ between the two spellings: it asserts that nothing is reported under /lib, /bin or /sbin where those are links, and that each vendor unit file is reported exactly once.
Desktop environment mechanisms
Mint's Cinnamon is why this subsection exists. XDG autostart covers most desktop persistence, but Cinnamon additionally loads JavaScript applets, desklets and extensions into the session process at login, from ~/.local/share/cinnamon/applets, desklets, extensions and their /usr/share/cinnamon counterparts. Which ones are enabled lives in dconf under the Cinnamon schema, not in their presence on disk.
This is a real autostart mechanism that no existing Linux tool enumerates, and Mint being a supported target makes it tier one rather than a curiosity. GNOME Shell extensions (~/.local/share/gnome-shell/extensions) have the same shape and cover the other three distributions' default desktops, so this is one collector with two backends.
Reading enablement means parsing dconf's binary database directly, since shelling out to gsettings or dconf is barred by §3. The dconf_rs crate is not an option despite its download count — it invokes Command::new("dconf").
Resolved: the gvdb crate (v0.10.1, actively maintained) reads the glib gvdb format in pure Rust. Its default feature set pulls only zerocopy, serde and zgvariant; the glib C binding is an optional feature and stays off. The same crate also reads /usr/share/glib-2.0/schemas/gschemas.compiled, which is the other half of the answer — the user database only contains keys the user has changed, so schema defaults are needed to know what is enabled on an untouched account.
Three caveats:
• dconf is layered. /etc/dconf/profile/user names the database stack, system databases live in /etc/dconf/db, and locks can pin a key. Full resolution means reading the profile and walking the stack, not just the user file.
• The gvdb crate is written for GResource. Verified: it reads a real ~/.config/dconf/user, as written by a GNOME and a Cinnamon session booted in CI, and system databases compiled by dconf itself, locks included.
• zgvariant has very few downloads. Same bus-factor note as rpmdb (§7): be ready to vendor.
Deferred
GRUB and initramfs (pre-OS, needs image parsing), container runtimes, web shells (requires content heuristics, out of scope for a mechanical tool), Polkit rules, X11 ~/.xinitrc and ~/.xprofile.
The user-enumeration problem
Several collectors are per-user. With CGO-free static linking there is no NSS, so accounts come from parsing /etc/passwd directly. That misses LDAP and SSSD accounts.
Decision: enumerate the union of /etc/passwd entries, directories present under /home, /root, and any account named by a crontab spool file. Record the discovery source per user. Document the LDAP gap explicitly rather than silently under-reporting.
A spool file names an account but not its home. As built, such an account is given /home/<name>; see §15.
6. Enablement resolution
A unit file sitting in /etc/systemd/system may do nothing. A unit enabled through a .wants/ symlink will not appear in a naive directory walk as enabled. Conflating presence with enablement is the single most common defect in existing Linux autostart tools, and avoiding it is a large part of unbidden's value.
Live host: D-Bus
Talk to org.freedesktop.systemd1 on the system bus, calling ListUnitFiles and ListUnits on org.freedesktop.systemd1.Manager. Not /run/systemd/private: systemd's replies there carry no unique sender name, zbus panics reconstructing the message on its own executor thread where the panic cannot be caught, and the call waiting for it never returns. A scanner that hangs on the host under investigation is worse than one that answers "inferred". This gives authoritative UnitFileState (enabled, disabled, static, masked, linked, generated, transient) and the runtime ActiveState and SubState.
zbus speaks the wire protocol in pure Rust with no libdbus, which keeps the static-linking requirement intact.
Notes:
• Query the system manager and each user manager. User units live in a per-user bus that may not be running; absence of a user manager is not absence of user units, so the filesystem walk still reports the unit with its inferred enablement and DegradedEnablement.
• A user's bus socket is in that user's own runtime directory, so anything answering on it is the user's to control. Each manager is heard only about units that are its business: a system unit's enablement comes from the system manager, a unit in someone's home from the manager of the uid that owns that home in the account database, and a unit on the shared user search path from any user manager, which is then one account's answer and says whose. Every query has a deadline, so a bus that accepts a connection and never replies cannot hang a finished scan.
• Answers are keyed by the unit file's path with its directory resolved (§5, merged-usr). Keyed as systemd spells them, not one vendor unit on Debian 12, Ubuntu 22.04 or Mint 21 ever took systemd's answer.
• generated is significant: a generated unit came from a systemd generator, which is itself a persistence mechanism (§5, tier two). The unit is attributed GeneratedBy(systemd-generator) and noted as generated. An Unpackaged flag its target earned stays: the generator wrote the unit, not the program the unit runs. Linking each generated unit to the generator that wrote it is not done; see §15.
• D-Bus gives state for units systemd knows about. A unit file present on disk that systemd has not loaded still needs reporting, so the filesystem walk is the primary enumeration and D-Bus is the enrichment, never the reverse.
Fallback
Where D-Bus is unreachable — systemd not running, socket permissions, a container without a manager — fall back to resolving .wants/ and .requires/ symlinks across the unit search path and mark enabled accordingly, with a DegradedEnablement flag on the entry so the operator knows the answer is inferred.
This fallback is also the offline-root implementation (§11), which is a reason to build it in v1 even though D-Bus normally answers. Where D-Bus answers, the inferred value is kept as inferred_enablement, and CI compares the two on every unit systemd answers for with a comparable state (§13).
Precedence
The unit search path is ordered as §5 lists it. An admin-placed unit in /etc overriding a vendor unit of the same name is worth surfacing explicitly — it is both a legitimate admin action and a persistence technique. Emit both entries and record which shadows which on each (shadows, shadowed_by). The ShadowsVendorUnit flag goes on the overriding unit, the one that runs: the flag is a fact about what it does, and the shadowed one is only noted.
Two places the order is easy to get wrong: generator.early outranks /etc, and generator.late ranks below every vendor directory. And each account's user manager reads its home directories and the shared user directories interleaved, so a unit in ~/.config/systemd/user overrides the packaged one in /usr/lib/systemd/user for that account, and is flagged as doing so.
7. Provenance
This is the feature that makes unbidden worth building rather than another path-lister. It is the Linux answer to Autoruns' code-signature verification, and arguably a stronger signal.
Windows asks: is this binary signed, and by whom? Linux has no signature on arbitrary files, but it has something better — a per-file record of which package shipped it and what its contents were at install time. That turns "is this file supposed to be here?" from a judgement call into a lookup.
The verdict
For source and for target_path, resolve one of:
Verdict
Meaning
Packaged { package, version, integrity: intact }
Owned by an installed package and its hash matches the package manifest. Almost always uninteresting.
Packaged { package, version, integrity: modified }
Owned by a package but the contents have changed since install. High signal. This is a trojaned system binary or an edited unit file.
Packaged { package, version, integrity: conffile-modified }
A configuration file the package declares as such, changed since install, which is what configuration files are for. See Conffiles below.
Packaged { package, version, integrity: unknown }
Owned by a package that records no digest to check it against. Never read as intact.
GeneratedBy { by }
Written at runtime by a named component — snapd, a systemd generator, systemctl set-property, cloud-init. Neither packaged nor attacker-authored; see Snap below for what earns it.
Unpackaged
No package claims this file. Normal for admin-authored config, and exactly where attacker-authored persistence lives.
Unknown
No package database found, or the file is on a filesystem the database does not cover, or the database could not be read to the end (§3).
The source's verdict is the entry's provenance. The target's is recorded as target_provenance, and an unpackaged or modified target flags the entry: a packaged unit whose ExecStart= names something no package shipped is the whole shape of a hijacked service.
A command given as a bare name — ExecStart=systemctl, * * * * * root backdoor — is resolved against the mechanism's search path before any of this, so the file it names gets the same lookup as an absolute path would.
A target that is a symlink no package owns, or one the package database records no digest for, is judged by the file it finally resolves to, and says so. /usr/bin/editor -> /etc/alternatives/editor -> /usr/bin/vim.basic is vim; the same links pointed at /tmp end at an unpackaged file. This applies to what an entry runs, never to the entry's own source: an alias link in /etc/systemd/system is itself the evidence and keeps its own verdict.
Implementation
Read the databases directly. Never invoke rpm or dpkg (§3).
The supported platform set (§1) reduces this to exactly two backends, and simplifies the harder one considerably.
dpkg is straightforward: /var/lib/dpkg/status for installed packages, /var/lib/dpkg/info/*.list for file ownership, and /var/lib/dpkg/info/*.md5sums for integrity. All plain text. The file lists are streamed once per scan and only the paths the entries asked about are kept (Cost, below). Each path is looked up under every spelling a package might have recorded: the merged-usr aliases, and the path with its directories resolved on the host, which is what catches a list entry written through a symlinked directory.
Two dpkg-specific hazards, both of which would otherwise produce false PackagedModified findings at scale:
Conffiles. Configuration files are expected to differ from what the package shipped — that is what a conffile is for. dpkg records their original digests separately, in the Conffiles: field of /var/lib/dpkg/status, and checksum verification tools exclude them by default. unbidden must do the same: a conffile whose contents differ is Packaged and intact-by-policy, carrying a distinct ConffileModified marker rather than the high-signal PackagedModified flag. Without this, every host with an edited /etc/ssh/sshd_config lights up.
Missing md5sums. Not every package ships a .md5sums file. Where none exists, integrity is genuinely unknown and must be reported as Packaged with integrity Unknown, never as intact. Silently treating absent checksums as passing is how a scanner gives false assurance about exactly the file an attacker replaced.
A third, found in building it: dpkg's own maintainer scripts. /var/lib/dpkg/info/<package>.postinst is listed in no file list and has no digest anywhere, so ownership comes from the file name and integrity is always unknown. What can be established is when it changed. dpkg writes a package's .list and its scripts in the same unpack, and an inode's change time cannot be set from userspace, so a script whose ctime is more than two minutes after its package's .list was edited or planted by something other than dpkg. That is noted as changed_after_install. On an image that was copied rather than mounted the ctimes are the copy's, and the comparison only ever adds the note, never removes one.
rpm is the hard part. The database backend varies by RPM version: BerkeleyDB (Packages) on RHEL 7 and 8-era systems, ndb, or SQLite (rpmdb.sqlite) on RPM 4.16 and later.
With Fedora as the only supported rpm distribution, that reduces to sqlite alone. Fedora 33 changed the default rpmdb backend to sqlite, and BDB dropped to read-only support in Fedora 34, so no supported Fedora release carries a BDB database. As built, only sqlite is read; see the decision below. The corollary is that the rusqlite bundled-feature decision is not an edge case — it is the entire rpm path.
The database is read through Root like every other file (§11), capped, deserialised into an in-memory SQLite, and never opened in place: SQLite would try to create -wal and -shm files beside it, which writes to the host under examination and fails on a read-only image. rpm keeps the database in WAL mode, so the in-memory copy is switched to rollback-journal mode first; a transaction sitting in a live -wal during a concurrent dnf run is not seen. A scanner reads a snapshot.
Integrity follows rpm -V. A regular file is checked against RPMTAG_FILEDIGESTS in the algorithm RPMTAG_FILEDIGESTALGO names — absent or 1 is MD5, 8 is SHA-256, anything else is unknown. A symlink is checked against RPMTAG_FILELINKTOS: rpm records no digest for one, but it records the target. A %config file that differs is conffile-modified; a %ghost file is unknown.
Snap, and the limits of package provenance
Ubuntu and Mint ship snapd, which installs systemd units named snap.*.service along with mount units for each squashfs revision. dpkg owns none of these files. Under the §7 rules as written, every snap on the system reports Unpackaged — the same verdict an attacker's unit gets.
This is the largest false-positive source in the supported set, and it matters because Unpackaged is the flag the tool leads with. Options considered, in order of preference:
1. Read snapd's own state (/var/lib/snapd/state.json, and the /snap/<name>/<rev> layout) as a third provenance source, giving Packaged with a snap origin.
2. Treat units matching snapd's generated-unit naming convention as GeneratedBy(snapd), a distinct provenance verdict that is neither packaged nor unpackaged.
Option 1 is more work and correct; option 2 is cheap and covers most of the noise. The same GeneratedBy verdict also handles cloud-init on Ubuntu server images and systemd generators generally (§6), so it is machinery worth having regardless.
As built, option 2 with two rules that keep the verdict from being claimed by naming a file. Built on a name alone, it let snap.evil.service drop its Unpackaged flag, and it skipped the integrity check on packaged files with snap-like names, among them the setuid snap-confine.
• The package databases answer first, for every path. GeneratedBy is only ever considered for a path no package claims.
• A snap verdict needs the snap to be installed — an image for it in /var/lib/snapd/snaps — and the file to have the shape snapd gives it. A service or timer must carry X-Snappy=yes and run nothing but /usr/bin/snap run for that snap; a mount unit must mount an installed revision's image at that revision's own directory under /snap.
Output under /run/systemd/generator* is attributed to systemd-generator, /run/systemd/transient to systemd-transient, the system.control directories to systemctl-set-property, and /run/cloud-init to cloud-init. Only root can write any of them.
Option 1, reading state.json, is not done; see §15.
Spike, 20 Sep 2026 — superseded. The crate rpmdb (github.com/yybit/rpmdb-rs, MIT, v0.1.1) is a direct port of go-rpmdb and reads all three backends — bdb, ndb and sqlite3 — auto-detecting the format from the file. Its Package struct exposes base_names, dir_indexes and dir_names, which reconstruct the full owned-file list. Path-to-package ownership therefore works off the shelf.
File integrity does not. RPMTAG_FILEDIGESTS (1035), FILEMODES, FILESIZES and FILEFLAGS are all defined in the crate's tag table but none are parsed into Package, and RPMTAG_FILEDIGESTALGO (5011) is absent entirely. The header parser already works, so this is adding match arms to one function, not a port. Contribute upstream, and vendor the patch until it lands.
Two risks to carry:
• Static linking. The crate depends on rusqlite with default features, which links the system libsqlite3 dynamically and would break §3. Fix: declare rusqlite with the bundled feature in unbidden's own manifest so Cargo's feature unification applies it to the transitive dependency, compiling SQLite from source into the binary. Statically linked C is acceptable; dynamic linkage is not. The CI ldd check (§12) is what proves this holds.
• Bus factor. v0.1.1, single maintainer, ~2,000 downloads. Vendor it, or be prepared to fork. The format handling is a few hundred lines and go-rpmdb remains the reference.
Decision, as built: the crate is not used. It drops empty strings from string arrays, and the filesystem package owns /, whose base name is the empty string, so every later base name in the largest package shifts by one against its directory index and thousands of paths are silently misattributed; and, as the spike found, it parses none of the digest tags integrity needs. Wrong provenance is worse than none. unbidden carries its own header parser — the few hundred lines the bus-factor note anticipated — tested against headers built the way rpm writes them and, in CI, against the real rpmdb of each supported Fedora (§13). It reads sqlite only. BerkeleyDB and ndb are not supported, which costs nothing on the supported set and means RHEL 7 and 8 report provenance Unknown.
Note that RPM stores per-file digests in the header, so integrity checking is available without the rpm -V binary; the digest algorithm varies by package and must be read from RPMTAG_FILEDIGESTALGO.
Cost
Building a full path index would be the most expensive part of a scan. As built, there is no index: each backend streams its database once per resolution pass and answers only the paths the entries named, a few thousand against half a million packaged files on a desktop.
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
Hide entries that are Packaged and intact, and whose target is too — default on. This is the sysadmin's view and the IR triage starting point.
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
• ConffileModified — package owns it as a configuration file, and it has been changed since install
• TargetMissing — command resolves to a non-existent path
• TargetUnresolvable — command could not be parsed into a path at all
• WorldWritable — source file or its parent directory is writable by anyone. The parent is the directory that actually holds the file, followed through links, and a sticky one such as /tmp does not count: a symlink's own mode is always 0777 and means nothing.
• OwnerMismatch — a file under a user's home is owned by a different user
• HiddenPath — a directory on the source's path, or on where its links lead, is dot-prefixed (other than the conventional .config, .local, .cache, .ssh, .var and .git), or it lives under /tmp, /dev/shm, /var/tmp. Not yet applied to the command's target; see §15.
• NonStandardLocation — a unit or module outside the standard search path for its kind
• ShadowsVendorUnit — overrides a same-named unit later in the search path (§6); set on the overriding unit
• DegradedEnablement — enablement inferred rather than authoritative (§6)
• EncodingAnomaly — command contains non-UTF-8 bytes, or base64/hex-looking payloads over a length threshold
EncodingAnomaly is the closest thing to a heuristic here and is deliberately narrow: it reports an observable property of the bytes, not an inference about intent. The thresholds are 48 characters for a base64-alphabet run and 160 for a hex run.
Flag-like facts that are not flags ride in raw notes rather than widening the flag set: changed_after_install on a maintainer script (§7), target_is_unpackaged_suid on an entry whose target is an unpackaged setuid binary (§14.4), not_followed on a home link that leaves its home (§3).
Why no scoring
A 0-to-100 risk number would have to be invented, could not be justified per-entry, and trains operators to filter on it and miss everything below the cut. The flags compose into filters that the operator controls (--flag unpackaged --flag world-writable), which is the same power with none of the false authority.
A rule engine remains possible later precisely because the Entry record (§4) carries the raw facts. Nothing here forecloses it.
Suppression is a rendering behaviour, not a scan behaviour: --json always emits every entry, and the human table always states how many it hid. See §14.3 for the exact rule.
Flags requiring cross-entry knowledge — ShadowsVendorUnit, and LD_PRELOAD assignments found in any collector's output — are applied by the enrichment pass described in §14.4, not by collectors.
9. Baseline and diff
Noise is the problem that kills tools in this category.
Provenance filtering (§8) handles most of it; diffing handles the rest, and is what makes unbidden useful as a periodic control rather than only a one-shot.
Model
A scan with --save writes a snapshot. A scan with --against emits the same Entry stream annotated with a delta: Added, Removed, Changed with the names of the changed fields, or Unchanged.
Entry identity (§4) is what makes Changed meaningful rather than a churn of add/remove pairs. A backdoor that rewrites its own ExecStart line shows up as one changed entry naming command and target_sha256.
A change to mtime alone is Unchanged: systemd rewrites every generated unit on each daemon-reload, and a diff full of byte-identical rows is one nobody reads. The field stays in the record. Raw notes prefixed live. — a loaded module's reference count — describe the running machine rather than its configuration and are not compared.
Snapshot format
The snapshot is one JSON object, {header, entries}: the record stream of §10 with its header. The header records hostname, kernel version, distro (id, version, and the ID_LIKE base), scan time, unbidden version and schema version, whether the root was live and the scan deep, whether it ran as root, where enablement came from (systemd-dbus or inferred), which collectors ran and how each went — complete, partial with the paths it could not read, skipped with the reason, or failed with the error — and any enrichment stage that failed. Reads a collector deliberately limited (§3) are listed too, and do not make it partial.
That matters. A baseline taken when the rpm collector errored is not comparable to one where it succeeded, and the diff must say so rather than reporting every RPM-owned entry as newly appeared. The diff refuses, naming why, when the two differ in any collector's status, in depth, in privilege, in where enablement came from, or when either carries an enrichment failure.
One consequence: a live scan and an offline scan of the same host are not comparable, even though their entry ids match (§4). Offline, the kernel collector is partial for want of /proc/modules and enablement is inferred. See §15.
Expected workflow
• Sysadmin: baseline a known-good machine of a given role, compare its fleet-mates by hand.
• IR: baseline a clean image of the same build, compare the suspect host.
• Either: baseline before a change window, compare after.
This is the pattern MITRE CAR-2013-01-002 describes for Autoruns, periodic collection and comparison for differences, and it transfers directly.
10. Interfaces
CLI
Subcommands: scan (the default when none is named) and explain <entry-id>; tui is v1.1.
Scan flags: --all to disable suppression, --json for the record stream, --pretty with --json for one indented {header, entries} object, --kind and --trigger and --flag as filters, --deep for tier three, --save <path> to write a baseline, --against <path> to compare with one, --root <path> to scan a mounted image or chroot (§11).
explain takes --no-source (§14.2), --from <baseline> to explain an entry as a saved scan recorded it, and --root and --deep as scan does.
Defaults matter more than options here. Bare unbidden with no arguments serves the sysadmin: suppressed, readable, sorted by kind. --all --json serves the responder. Neither audience should have to read the manual to get their view.
explain dumps everything known about a single entry including the raw source text it was parsed from, which is what an analyst actually wants after spotting a row.
JSON
Newline-delimited: the header on the first line, then one Entry per line, so output streams and survives truncation. --pretty gives the snapshot form of §9, indented, for humans reading it directly. With --against, each line is the entry plus its delta.
The schema is a compatibility contract from 0.1 onward: additive changes only, version recorded in the header. This is the primary interface — the TUI and the human table are views over it, and any fact visible in either must be present here.
TUI
ratatui. Kinds on the left, entry list centre, detail pane right. Filter by flag, toggle suppression, mark entries reviewed, view the backing file.
Explicitly a v1.1 target. The CLI and JSON have to be right first: a TUI built early risks bending the record shape to fit the widget rather than the reverse.
11. Designing for offline roots
Decision from scoping: live host only in v1, but nothing may foreclose offline analysis of a mounted image or chroot. Retrofitting this later means touching every collector, so the constraints go in now.
The Root abstraction
No collector may name an absolute path directly. All filesystem access goes through a Root handle that resolves paths relative to a scan root, defaulting to /.
In practice: root.open("etc/systemd/system"), never File::open("/etc/systemd/system"). A lint or a #[deny]-style convention should enforce this, because one collector reaching for an absolute path silently breaks offline mode for everyone.
As built, a test lexes every source file, skips only #[cfg(test)] items, and refuses any filesystem call outside root.rs, which is Root, and main.rs, which reads and writes the operator's own baseline files. It covers provenance, enrichment, account discovery and D-Bus as well as collectors. The same test refuses anything that executes a program (§3).
Root also owns the symlink policy from §3. An offline root makes this urgent rather than theoretical: a symlink inside a mounted image pointing at /etc/passwd resolves to the analyst's /etc/passwd, not the image's. Every resolution must be confined to the root, which means openat2 with RESOLVE_IN_ROOT where the kernel supports it and manual path confinement where it does not.
As built: openat2 with RESOLVE_IN_ROOT and RESOLVE_NO_MAGICLINKS where the kernel has it (5.6 and later). Where it does not, Root resolves every link itself, inside the root — an absolute target restarts at the scan root and .. stops there, the way RESOLVE_IN_ROOT resolves — and then opens the result one component at a time, refusing links, so anything swapped in after the resolution fails rather than escapes. On a live root, / is the root, and a plain openat cannot escape it. Reading a link resolves its parent directories the same way.
One access is not confined on an offline root without that care from the caller: extended attributes. Linux gained getxattrat only in 6.13, and fgetxattr refuses an O_PATH descriptor, so the capability read in the deep walk names the path, and relies on the walk having entered every directory without following a link. That rule is written where the call is made.
What offline costs
Two capabilities do not survive:
D-Bus enablement (§6). There is no running systemd in a mounted image. This is why the symlink-resolution fallback is a v1 deliverable rather than a contingency — it is the offline implementation, tested continuously on live hosts where its answers can be checked against D-Bus. That validation loop is only available while both paths exist.
Live-only facts. Loaded kernel modules, running processes, and current mounts are absent. The affected collectors must degrade to their on-disk sources and mark the entry rather than omitting it.
As built, the kernel collector checks for a live root itself, reports every on-disk module with its loaded state unknown, and marks itself partial with the reason. The Collector trait has a requires_live declaration, but no collector uses it, because the kernel collector's on-disk half still runs offline; see §15.
Rules for v1
1. Every path goes through Root.
2. The symlink-resolution enablement path ships in v1 and is tested against D-Bus for agreement.
3. Any collector reading a live-only interface declares it, so the offline mode knows what to skip.
4. Distro and version detection reads from the root (/etc/os-release), never from the running system.
12. Build and dependencies
Target
x86_64-unknown-linux-musl and aarch64-unknown-linux-musl, fully static. Verified in CI, on every build and on the binaries a release attaches, because a regression here is a silent loss of the §3 guarantee rather than a visible break. The check reads the ELF headers: no program interpreter, no NEEDED entry. Not ldd, which calls every binary built for another architecture "not a dynamic executable" and so passed any aarch64 build whatever it was.
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
hand-rolled header parser
sqlite backend only; see §7 for why the rpmdb crate is not used
SQLite
rusqlite, bundled and serialize features
Compiles SQLite from C source, statically linked; the database is deserialised from bytes read through Root, never opened in place
dconf, compiled schemas
gvdb
Default features only; the glib C binding stays off (§5)
dpkg digests
md-5
dpkg's manifests are MD5
dpkg
hand-rolled
Plain text, not worth a dependency
Shell text
tree-sitter, tree-sitter-bash
The grammar and its C runtime, statically linked, about 1.5 MB. Table-driven, so text nested 50,000 deep parses in linear time; yash-syntax and brush-parser recurse per level and overflow the stack at 1,000 and 10,000
Binary constraints
Single binary, no config file required, no runtime data files. Anything it needs to know about paths and mechanisms is compiled in. The operator copies one file to a host and runs it.
Size is not a concern but should be watched — a 50 MB binary is awkward to move onto a host over a constrained channel.
13. Testing
PANIX as ground truth
PANIX (github.com/Aegrah/PANIX) is a Linux persistence framework that installs 37 mechanisms, each with a paired revert script and a MITRE ATT&CK mapping. It is an offensive tool and contains no enumeration code, so it is not a dependency — it is the test fixture.
The loop, per mechanism, on a disposable machine:
1. Snapshot baseline with unbidden.
2. Plant the mechanism with PANIX.
3. Scan. Assert the entry appears, with the expected kind, source, command and flags.
4. Revert with PANIX.
5. Scan. Assert the diff is clean against the baseline.
Step 5 is as valuable as step 3: it catches collectors that report stale or phantom entries, which is how a tool loses an operator's trust permanently.
This gives real adversary-shaped fixtures rather than hand-written ones, and PANIX's mechanism list doubles as the coverage matrix for §5. A mechanism PANIX implements that unbidden does not detect is a tracked gap with a name and a technique ID.
As built, ci/panix-coverage.tsv is that matrix. It has one row per PANIX module, 37 in all, each with its ATT&CK technique as PANIX's own table gives it.
• An in-scope row says which entry kinds count, the pattern the source must match, the flag it must carry, and a marker — the callback port every planted payload dials — that must appear in the entry's command, its notes, or the file it was read from or runs. Step 3 passes only when one entry satisfies the whole row.
• An out-of-scope row gives the reason and the section of this spec that makes it one. The accounts and credentials modules are a way in rather than something that executes. Bind and reverse shells are processes, which survive nothing. A wrapped system binary runs when a person runs it. GRUB, initramfs, Polkit, container escapes and web shells are deferred by §5, and rootkits are excluded by §2.
• A mechanism PANIX cannot plant is a failure, not a skip: an untested mechanism must not read as a passing one. A module PANIX adds upstream without a row fails the run.
• A difference after revert whose file is still on disk is PANIX's leftover, and the loop re-baselines past it. One whose file is gone is a phantom, and fails.
Where the loop runs: in a VM for the distributions that publish cloud images (Debian, Ubuntu, Fedora), with a real boot and a kernel of its own. Mint and LMDE publish none, so they run in a privileged container booted with systemd as PID 1. That gives the mechanisms a real service manager, system bus and timers, but not a kernel of their own, so lkm alone is not run there, and the loop says so.
The loop gates a release.
Distro matrix
The four supported distributions from §1, all in CI, all gating release: Debian 12 and 13, Ubuntu 22.04 and 24.04, Linux Mint 21.x and 22.x plus LMDE, and Fedora current and current-1.
The PANIX loop above runs against every one of them. That is the point of automating it — thirty-odd mechanisms across nine images is not a matrix anyone verifies by hand, and the distro-specific defects are exactly the ones that hide.
The published Mint 22 container image carries Ubuntu's base-files and reports itself as Ubuntu 24.04. CI installs Mint's own base-files from the Mint repository the image's apt sources already name, and asserts the result reports Mint 22 before testing it.
Desktop coverage needs care. Both desktops matter for the extension collector (§5), and a headless image will silently skip it, so at least one image per desktop must boot a session. As built: Mint 21 with Cinnamon and Debian 12 with GNOME, each under Xvfb. The session writes a real user dconf database, and an extension is then enabled the way the desktop does it. A system database compiled by dconf itself pins a second extension with a lock, which must demote the user's own choice.
Specific things to assert per distro, because they are the ones a generic test misses. All are asserted in CI:
• Merged-usr: nothing is reported under /lib, /bin or /sbin where those are links, and every vendor unit file is reported exactly once (§5).
• The package manager as referee, on every image: every file-backed verdict must agree with the distribution's own tool. The owner must be the one rpm -qf or dpkg-query -S names, every file called intact must pass rpm -V or dpkg --verify, and every file called unpackaged must be owned by nothing. unbidden never runs those tools (§3); the test does, to know unbidden is right.
• Fedora: the rpm path exercises sqlite, file digests are read correctly given RPMTAG_FILEDIGESTALGO (the referee above), and SELinux is enforcing and blocks nothing (the VM).
• Debian family: an edited conffile reads as conffile-modified and never raises PackagedModified. A package whose md5sums are taken away reads integrity Unknown, and is shown by default rather than hidden (§7). No maintainer script on a pristine image, or after a real package install, reads as changed after install; one image also edits one after the install window and requires the note.
• Ubuntu: installed snaps do not flood the output as Unpackaged, and at least one is attributed to snapd (§7). The Mint images carry no snapd.
• LMDE: unbidden's header reads the Debian base as such, not as Ubuntu.
• On a running system (the VMs and the systemd containers): every collector is complete as root, enablement came from systemd, and the symlink fallback agrees with systemd on every unit systemd answers for with a comparable state (§11 rule 2).
• Everywhere: a unit planted in /etc/systemd/system and one in /usr/local/lib/systemd/system are both found and unpackaged. A command carrying terminal control sequences is shown escaped. A home link to /etc/shadow is recorded, not read, and leaves the scan comparable.
RHEL, CentOS, Arch, openSUSE and Alpine are not tested. Community bug reports welcome; no release waits on them.
Parser fuzzing
Every parser gets a cargo-fuzz target. §3 establishes that parser input is adversarial; fuzzing is how that stops being an aspiration. Priority order: unit files, crontabs, .desktop files, udev rules, PAM configs.
As built: 37 targets, one per parser. The five above get a minute each in CI, the rest twenty seconds; a smoke run, not a soak. The input is delivered as the adversary delivers it, as a file on a scan root read through Root with its caps and link rules. Parsers that run in enrichment — the package databases, script interpreter lines, the preload entries — are reached by running enrichment too. A panic in a collector or in an enrichment stage fails the target. Seed corpora come from real files in the supported images. One parser has no target: the security.capability extended attribute, which an unprivileged fuzzer cannot set.
Golden files
Collector output for a fixed synthetic filesystem tree, checked into the repository. Catches unintended changes to the Entry record, which is the schema contract of §10. Alongside it, a mutation pass takes the same tree apart 120 ways and requires every collector to survive each.
Conventions
The rules of §3 and §11 are enforced by a test rather than trusted: no module but Root touches the filesystem by path, nothing executes a program, and no string literal carries the run of spaces a lost line continuation leaves. The CI scripts themselves are shellchecked.

14. Resolved decisions
All seven questions from the first draft are answered, and three more were settled in building it. Where building one changed the answer, the entry says so. What is still open is in §15.
1. RPM database access — resolved
See §7. The spike found the rpmdb crate usable with a patch; building on it found that it misattributes the filesystem package's files, so the header format is parsed in-house and only the sqlite backend is read, which is the whole of the supported set.
2. Raw source text in explain — yes, and it changes the command's shape
explain includes the source text by default; scan never does, at any verbosity. The distinction is consent: explain <id> is a deliberate request for one entry, while scan --json output gets pasted into tickets and chat.
--no-source suppresses it. Excerpts are capped — the whole file under 64 KB, otherwise the matching region plus twenty lines either side.
One consequence worth building in deliberately: explain re-reads the file rather than replaying what the scan captured, and reports when the current hash differs from the one the scan recorded. On a live compromised host, an entry that changed between scan and inspection is itself a finding.
As built, explain <id> with no other argument scans afresh to find the entry, so the comparison is between two reads moments apart. It is meaningful with --from <baseline>, which takes the entry, and its recorded hash, from a saved scan. Where the entry's command cannot be found in a file too large to show whole, the first twenty-one lines are shown. Everything printed from the file passes through the terminal escaping of §3.
3. Suppression default — suppression is presentation, never data
The root cause of this question is a category error in the first draft: suppression was specified as a scan behaviour when it is a rendering behaviour. Fixing that removes the risk entirely.
Three rules:
1. --json implies --all. Machine output is always complete; filtering is the consumer's job. A responder cannot miss an entry they were never shown, because the JSON always shows everything.
2. The human table suppresses by default and always prints a trailer naming the count: 142 entries hidden (packaged, intact) — use --all. Never silent.
3. Suppression tests Packaged AND intact. A PackagedModified entry is never suppressed. This is the highest-signal finding the tool produces and it lives inside the category being hidden, so it gets an explicit test case, not just a sentence here.
As built, the whole rule. An entry is hidden only when all three of these hold:
• It carries no flag but DegradedEnablement. That flag is a caveat about how the answer was reached, set on every unit where systemd is not running, and letting it block suppression would hide nothing there.
• What it runs is verified: its target is packaged and intact, or is a packaged directory, which has no digest to hold. Otherwise it would be the missing-md5sums case, one step removed.
• Its own file is packaged and intact, or it is the package manager's own machinery: an rpm scriptlet read out of a package header, or a dpkg maintainer script. No package manager records a digest for its own metadata, so these can never be verified, and an ordinary Debian host carries hundreds. §7 already takes the database at its word about who owns every file, so hiding what the database itself holds adds no exposure. The exception is a maintainer script whose inode changed after its package was installed (§7): dpkg did not write that, and it is shown.
A conffile that has been edited carries ConffileModified and so is shown. It is not a finding, but it is a local change, and the default view is where an administrator expects to see those.
4. LD_PRELOAD correlation — add an enrichment phase
The question was framed as "how far to chase LD_PRELOAD", but the real issue is that some facts are inherently relational and the pipeline had nowhere to put them. ShadowsVendorUnit (§6) has the same problem and was already specified without a home.
Resolution: three phases, not two.
1. Collect. Collectors stay independent, know nothing of each other, run in parallel, emit Entries.
2. Enrich. A pass over the assembled Entry set adds flags that require cross-entry knowledge: LD_PRELOAD assignments found in any collector's captured environment, unit shadowing, a cron job whose target is also an unpackaged SUID binary. Package provenance, D-Bus enablement and the interpreter chain of §5 live here too. Each stage runs isolated (§3).
3. Render. Suppression, filtering, output.
So yes, chase LD_PRELOAD everywhere — unit Environment= and EnvironmentFile=, shell profiles, PAM pam_env configs, /etc/environment, systemd environment.d — because collector independence is preserved. Each collector records environment assignments it encounters as ordinary Entry data; the enrichment pass interprets them, emitting one ld_preload entry per library per file that names it. LD_AUDIT and LD_LIBRARY_PATH are chased the same way.
This phase is where a rule engine would eventually live (§8), which is a second reason to establish it now.
5. Name and namespace — decided
The repository lives under a personal GitHub account as unbidden. No organisation. GitHub redirects on transfer, so moving it to an org later costs no broken links or stale clone URLs.
Verified free on 20 Sep 2026: crates.io, PyPI, npm, and Ubuntu 24.04 main and universe. The dormant GitHub org named unbidden is irrelevant under this decision.
Done: unbidden 0.1.0 is on crates.io with the code, and the repository is github.com/tire-fire/unbidden.
6. Licence — MIT, decided
MIT. Permissive, so the tools most likely to embed unbidden can: Velociraptor (Apache-2.0), osquery (Apache-2.0 or GPLv2), Wazuh (GPLv2), and commercial IR vendors, which are most of the market. A copyleft licence would block exactly the adoption that makes broad mechanism coverage worth maintaining.
Two consequences accepted deliberately:
• No patent grant. The Rust convention is Apache-2.0 OR MIT because Apache-2.0 adds an express patent licence and a retaliation clause. MIT has neither. Low risk for a tool that reads files and parses formats, but it is a real difference rather than a stylistic one, and worth revisiting if the project starts taking corporate contributions.
• A vendor can fork and close it. For a project whose value is breadth of coverage rather than a defensible core, reach is worth more than reciprocity.
7. Non-root behaviour — degrade, and make it structural
Run degraded, never refuse. But a warning banner is not enough, because partial output that looks complete is worse than no output.
Collector status is already part of the snapshot header (§9). Extend it: each collector reports Complete, or Partial with the list of paths it could not read. The human table prints a banner, the JSON header carries the detail, and — the part that matters — a baseline taken non-root refuses to diff against one taken as root. §9 already requires the diff to reject mismatched collector status, so this needs no new machinery, only a test.
The same structure has to be kept out of reach of the accounts being examined: only a path the scan could not read makes a collector partial, never content an unprivileged user wrote (§3).
8. Collector scope — resolved by cost class, not time
"Tier two if time allows" was not a criterion. §5 now splits collectors by cost: fixed-path collectors all ship in v1, and the three that need a full filesystem traversal move behind --deep as tier three. Sudoers ships as a line-level scan, labelled as such.
9. Entry id width — resolved, full 256 bits
Truncating to 64 bits was wrong. §4 carries the arithmetic: a targeted collision against a host's entry set costs roughly 2^53, and the payoff is a silently dropped row. Store the full hash, display a 12-character prefix, resolve unique prefixes on input.
10. dconf reading — resolved
The gvdb crate reads the format in pure Rust with default features. §5 has the detail and the three caveats, the second now verified against real databases. The extension and applet collector stays tier one.
11. Where a link out of a home leads — resolved
Recorded, not followed, and judged on where the whole chain ends rather than on its first hop (§3). A home that is itself a link is judged by where it resolves; a dotfile manager's links within one home are followed as before.
12. What an unprivileged user can do to a baseline — resolved
Nothing that makes it incomparable. A refused link, a capped read, an unparseable database are limited reads, reported but not partial (§3, §9). Before this, any account could make every later --against refuse to run.
13. Which user manager to believe — resolved
Only the one that owns the unit (§6).
15. Since v0.1, and what is open
The two unknowns v0.1 named — rpmdb against a genuine Fedora database, gvdb against a genuine user dconf file — were settled by contact with real systems, as it predicted. The first went against the crate (§7); the second went for gvdb (§5).
Contact with real systems also found these, now fixed and described in the sections above:
• §3: a home link judged on its first hop let ../../etc/shadow through.
• §3: user-controlled content could make collectors partial.
• §3: terminal control sequences reached the operator's terminal raw.
• §3: enrichment had no panic isolation.
• §3: a symlink loop, or a file where a directory belongs, inside a home made a collector partial. Both are recorded as limited reads now; a permission error, or a loop outside any home, still makes the collector partial.
• §3: nested shell text — $(...), backquotes, eval, sh -c text and wrappers — was followed without bound, so one user unit could exhaust a root scan's memory or stack. One depth budget now covers all of them, and past it the program reads as unresolvable.
• §3: one command line could add an entry per program in it, without limit. At most 32 are listed; the carrier records how many there are.
• §4: an entry synthesised from shell text could share an id with a shebang-chain entry, which makes a diff refuse to run, and two lines starting the same program kept only one trigger. These entries are keyed by the entry that declared them, and a last pass over every entry gives any remaining collision a suffixed name.
• §5 and §6: /usr/local/lib/systemd was never walked, and the generator directories' precedence was wrong.
• §5: every per-account unit read as non-standard-location.
• §5: environment.d drop-ins were reported twice on merged-usr hosts.
• §5: /usr/local/lib was not read for udev rules, modprobe.d, modules-load.d or environment.d, nor /run/modprobe.d, ~/.config/environment.d, /usr/lib/pam.d or the session autostart directories under /etc/xdg.
• §6: D-Bus answers never matched a vendor unit on distributions whose systemd names /lib.
• §6: one account could answer for another's units.
• §7: the snap verdict could be claimed by naming a file, and ran before the package databases.
• §7: bare command names were never looked up.
• §7: a target whose provenance lookup failed read as verified, and its entry could be hidden.
• §5: a wrapper — env, nice, nohup, sudo, timeout, flock, a shell given a script or -c text, and the like — stood in for the program it runs, and vouched for it.
• §5: shell text was read as one program. Each program in it is now an entry of its own, declared by the carrier, and builtins name no program.
• §5: a command's first word kept the shell operator after it, so /opt/a.sh; was the target of a cron line.
• §5: a Python module or script was not followed to the programs it starts; a dnf plugin module is one.
• §5: shell text was split by a lexer written for unbidden. The bash grammar splits it now, so the headers of for, case and select are no longer read as commands, and command, time with options and xargs are looked through; builtin names no program.
• §7: rpm symlinks were never verified.
• §7: maintainer scripts were hidden whatever had been done to them.
• §11: offline roots were refused outright on kernels before 5.6.
• §12: the aarch64 static check could not fail.
• §13: CI reported Mint 22 as Ubuntu, could not plant dbus on Fedora, checked snaps against one with no service, and failed at random on a KVM permission race.
• §13: the PANIX loop had never run, checked only an entry's kind, counted an unplanted mechanism as a skip, and gated nothing. PANIX's own systemd module plants into /usr/local/lib/systemd/system, the directory §5 was not walking.
Open. Each is a known departure from this spec or a gap in it, with what is true today:
• Cron identity includes the command, so an edited cron job diffs as removed plus added (§4). Changing it needs a different notion of which cron line is "the same line", and none suggests itself that the duplicate-id guard would not then trip on.
• An account found only through a crontab spool is given /home/<name> as its home, which may not be where its files are (§5).
• A D-Bus policy file in system.d that names no activatable service is not an entry of its own (§5).
• The interpreter chain follows one hop: from a script to its interpreter, to a file it sources or execs by full path, or to a program a Python file starts with a literal argument. Programs named in shell text are found through wrappers and the search path, but a program named by a variable or built at run time reads as unresolvable rather than followed (§5).
• The wrapper table is incomplete, and an option of a wrapper it does not list is skipped as one word rather than making the target unresolvable (§5).
• A generated unit is attributed to systemd-generator but not linked to the generator entry that wrote it (§6).
• snapd's state.json, option 1 of §7, is not read; the snap verdict rests on the installed images and the unit's shape.
• BerkeleyDB and ndb rpm databases are not read, so RHEL 7 and 8 report provenance Unknown (§7).
• HiddenPath is not applied to the command's target, so ExecStart=/tmp/x is flagged Unpackaged and TargetMissing or not on its merits, but not HiddenPath (§8).
• A live scan and an offline scan of the same host cannot be diffed against each other, because the kernel collector is partial offline and enablement is inferred (§9, §11). The Collector trait's requires_live declaration is unused.
• Extended attributes on an offline root are read by path, relying on the deep walk never following a link to reach one (§11).
• The security.capability parser has no fuzz target, since an unprivileged fuzzer cannot set the attribute (§13).
• The PANIX loop compares each scan with its baseline, and the diff refuses when any collector's coverage differs between the two. A collector that is partial on one scan for an unrelated reason therefore hides a detection by another (§13); an LMDE run missed dbus this way.
