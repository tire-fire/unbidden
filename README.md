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

## Licence

MIT.
