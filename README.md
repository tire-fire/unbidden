# unbidden

A Linux autostart and persistence enumerator. Rust, statically linked,
read-only.

It answers one question exhaustively: **what runs here that nobody asked for
right now?** Boot, login, authentication, elapsed time, network state change,
package installation, device attachment and shell startup are all in scope.
The subject is the trigger, not the subsystem.

```
$ unbidden
ID            KIND          ENABLED   NAME              FLAGS                    COMMAND
8f4e03c59dff  systemd_unit  enabled   telemetry.service unpackaged,hidden-path   /tmp/.cache/agent
cd855e96a2b2  cron          enabled   382e5e43cd2a      unpackaged               LD_PRELOAD=/tmp/h.so /usr/bin/x
92036d59408a  ld_preload    enabled   /tmp/h.so         unpackaged,target-missing LD_PRELOAD=/tmp/h.so

3 entries shown, 9 collectors ran.
1046 entries hidden (packaged, intact) — use --all
```

That last line is the point. A desktop carries a thousand legitimate autostart
entries, and a tool that lists all of them has told you nothing.

## What it does differently

**Provenance instead of guesswork.** Windows tools ask whether a binary is
signed. Linux has something better: a per-file record of which package shipped
it and what its contents were at install time. unbidden reads the dpkg and rpm
databases directly and reports, per entry, whether a package owns the file and
whether its bytes still match the manifest. "Is this supposed to be here?"
stops being a judgement call. Entries that are packaged and intact are hidden
by default; a packaged file whose contents have changed never is.

**Enablement, not presence.** A unit file in `/etc/systemd/system` may do
nothing, and a unit enabled through a `.wants/` symlink does not look enabled
in a directory walk. unbidden asks systemd over D-Bus where it is running, and
falls back to resolving the symlinks itself where it is not — marking the
answer as inferred when it did.

**Mechanisms nobody else enumerates.** Cinnamon applets and GNOME Shell
extensions load code into the session at login, and whether they are enabled
lives in dconf's binary database rather than on disk. unbidden reads that
database directly.

**Stable identity, so diffs mean something.** Each entry's id is a hash of its
mechanism, its source file and its name — never its contents. A backdoor that
rewrites its own `ExecStart` line shows up as one *changed* entry naming
`command` and `target_sha256`, not as an unrelated removal and addition.

## Use

```sh
unbidden                          # the readable view: noise suppressed
unbidden --all --json             # every entry, one JSON record per line
unbidden --flag unpackaged --flag world-writable
unbidden --kind cron --trigger login
unbidden --deep                   # also SUID binaries, file capabilities, git hooks
unbidden --save baseline.json     # record this host
unbidden --against baseline.json  # and compare later
unbidden explain 8f4e03c59dff     # everything about one entry, with its source text
```

`--json` always emits every entry: machine output is complete, and filtering is
the consumer's job. The human table always says how many rows it hid.

## What it will not do

It never executes anything on the host it is examining. `rpm`, `dpkg`,
`systemctl`, `crontab` and `ls` are all binaries on that host, and wrapping
them is a standard persistence technique — a wrapper that filters its own entry
out of the output is trivial to write. Every fact comes from reading a file, a
directory or a kernel interface, or from speaking D-Bus to systemd over a
socket.

It is statically linked for the same reason. `/etc/ld.so.preload` is itself a
persistence mechanism, and a dynamically linked scanner hands the attacker's
shared object into its own address space before `main()` runs. A static binary
never invokes `ld.so`.

It only reads. It does not disable, remove, quarantine or modify anything.

## The limit worth stating plainly

**unbidden cannot see past a kernel-level compromise.** If an attacker has
kernel code execution, every syscall unbidden makes can be lied to, and a
loaded module that hides itself defeats userspace enumeration by construction.
unbidden lists loaded modules but makes no claim to detect hidden ones.

It is useful against the overwhelming majority of real persistence, which is
userspace and file-backed. It is not a rootkit detector, and a clean report is
not proof of a clean host.

**Accounts come from `/etc/passwd`, so network directories are a gap.** A
static binary has no NSS, which is the price of not handing an attacker's
shared object into the scanner's own address space. unbidden widens the set
with every home directory and crontab spool actually present on disk, and
records on each entry how that account was found — but an LDAP or SSSD account
with no local trace and no home on this machine will not be enumerated, and
its per-user autostart will not be scanned.

Also outside its reach: a compromised build toolchain, and running it from a
share mounted on the suspect host.

## Supported platforms

Correctness on these is a release requirement.

| Distribution | Versions | Packages | Desktop |
| --- | --- | --- | --- |
| Debian | 12, 13 | dpkg | — / GNOME |
| Ubuntu | 22.04, 24.04 LTS | dpkg, snap | GNOME |
| Linux Mint | 21.x, 22.x, LMDE | dpkg | Cinnamon |
| Fedora | current, current-1 | rpm (sqlite) | GNOME |

Mint 22.x is supported and is the one row with no image of its own in CI,
because no honest one exists. Mint publishes ISOs and nothing else:
`linuxmintd/mint22-amd64` is an Ubuntu 24.04 rootfs with Mint's apt repository
attached and reports `ID=ubuntu`, and the only Mint 22 rootfs that does report
`ID=linuxmint` — the Incus community image — is Mint 22's `base-files` over a
22.04 userland, jammy `sources.list` and dpkg 1.21 included, so it would report
jammy packaging under a Mint 22 name. An image that merely carries the name
fails the distro check rather than passing quietly.

What Mint 22 is made of is covered in the pieces that do exist: Ubuntu 24.04 for
the noble base and its dpkg layout, `linuxmintd/mint21-amd64` for `ID=linuxmint`
and for a booted Cinnamon session, and LMDE 6 for the Debian-based variant.
Cinnamon's applet, desklet and extension directories and its dconf keys are
unchanged from 21.3 through 22.3, Mint ships no `/etc/dconf` in any release, and
the tool reads only `ID` and `VERSION_ID` out of os-release and branches on
neither. What goes untested is the string `22`.

Everything else — RHEL, CentOS, Arch, openSUSE, Alpine — is best-effort.
unbidden should run there and probably will, but nothing is tested and no
defect blocks a release. On a system with no package database it reports
provenance as `unknown` rather than calling every file unpackaged.

Only rpm's sqlite backend is read. Fedora moved to it in 33 and dropped
BerkeleyDB to read-only in 34, so no supported release carries a bdb or ndb
database.

## Build

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

Static musl is the supported build. `aarch64-unknown-linux-musl` works the same
way. The binary needs no configuration file and no runtime data: copy one file
to a host and run it.

## Testing

Three layers, each answering a different question.

```sh
cargo test
```

Unit tests per collector, plus two contract tests: a golden record of the
whole scan against a synthetic tree, which fails on any unintended change to
the Entry schema, and a mutation pass that takes that tree apart 120
different ways — truncating, corrupting bytes, splicing in NULs and quotes,
inserting 100 KB lines — and requires every collector to survive all of it.

```sh
docker run --rm -v "$PWD:/w" -w /w debian:12 sh ci/distro-check.sh /w/unbidden
```

Packaging and provenance against a real distribution: that the package
backend claims what it should, that entries verify intact against their
manifests, that an edited conffile does not raise the tool's highest-signal
finding, and that a unit planted in `/etc/systemd/system` is reported
unpackaged with its missing target flagged. Fast, and it runs on any image.

Derivatives are checked for the thing that makes them derivatives: LMDE must
read as Debian-based and mainline Mint as Ubuntu-based, and an image that
merely carries a distribution's name while being something else underneath
fails rather than passing quietly.

```sh
UNBIDDEN_DESKTOP=cinnamon docker run ... sh ci/distro-check.sh /w/unbidden
```

Boots a real Cinnamon or GNOME session under Xvfb, so the extension collector
reads a dconf database a session actually wrote rather than a synthetic one,
then has dconf compile a system database with a lock in it. That second half
is the layered stack: a profile names the databases, a system one answers for
every account, and a lock stops the account's own database answering at all —
which is how an administrator makes a setting mandatory and how an attacker
with root pins an extension on for everybody. This is the mechanism the spec
says no other Linux tool enumerates, and it is the only way to exercise it end
to end.

```sh
ci/vm-harness.sh                          # Debian 12, the whole matrix
ci/vm-harness.sh --image fedora-44
ci/vm-harness.sh --modules "cron udev systemd"
ci/vm-harness.sh --shell                  # boot and provision, then hand over
```

The real one. It boots a disposable VM from a cached cloud image, installs
[PANIX](https://github.com/Aegrah/PANIX) — a Linux persistence framework with
a paired revert script and an ATT&CK mapping per mechanism — and for each
mechanism runs the loop: baseline, plant, scan and assert the entry appears
with the right kind, revert, scan again and assert the diff is clean.

That last step is worth as much as the first. It catches collectors that
report stale or phantom entries after a mechanism is removed, which is how a
tool loses an operator's trust permanently.

A VM rather than a container because half the mechanisms need a real boot and
a running systemd, and because PANIX installs genuine persistence. Nothing
touches the machine you are sitting at: a cached cloud image, a copy-on-write
overlay discarded at the end, and qemu user-mode networking with one SSH port
on localhost. The planted payloads dial 127.0.0.1, so nothing leaves the VM.

It needs `qemu-system-x86_64`, `qemu-img`, `xorriso` and read access to
`/dev/kvm`. The static binary is built first, in a container if no musl
target is installed.

Mechanisms PANIX implements that unbidden does not detect are tracked by name
in `ci/panix-loop.sh` rather than quietly missing, and every one of them is
something §2 excludes or §5 defers: rootkits, GRUB, initramfs, polkit,
container runtimes, web shells, and user-account creation, which is not an
execution trigger.

## Licence

MIT.
