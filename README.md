# unbidden

Finds everything that runs on Linux without anyone asking.

[![ci](https://github.com/tire-fire/unbidden/actions/workflows/ci.yml/badge.svg)](https://github.com/tire-fire/unbidden/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/unbidden.svg)](https://crates.io/crates/unbidden)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![unbidden finding planted persistence on a Debian host](docs/scan.svg)

Boot, login, authentication, timers, device events, package operations, shell
startup — systemd, cron, udev, PAM, sudoers, SSH keys, XDG autostart, GNOME and
Cinnamon extensions, and a dozen other things. One tool, one record.

The useful part is what it leaves out. A desktop has well over a thousand
autostart entries, nearly all of them shipped by a package and unmodified.
unbidden reads the dpkg and rpm databases directly and hides those, so the
default view is the handful that are actually worth reading. In the screenshot
above, 1,690 entries were hidden to show those eight.

## Install

```sh
cargo install unbidden
```

Or grab a static binary from [releases](https://github.com/tire-fire/unbidden/releases) —
it's musl, so it runs anywhere from RHEL 7 to Alpine with nothing installed.

## Use

```sh
unbidden                          # the readable view
unbidden --all --json             # everything, one record per line
unbidden --flag unpackaged        # filter: packaged-modified, world-writable, ...
unbidden --kind cron --trigger login
unbidden --deep                   # + SUID, file caps, git hooks (walks the disk)
unbidden --save base.json         # and later:
unbidden --against base.json      # what changed?
unbidden explain 8f4e03c59dff     # everything about one entry, with its source
```

Entry ids are stable, so a backdoor that rewrites its own `ExecStart` diffs as
one *changed* entry naming the fields, not as an unrelated add and remove.

## What it won't do

It never runs anything on the host it's examining — `rpm`, `dpkg`, `systemctl`
and friends are all binaries an attacker can wrap. Everything comes from
reading files, directories and kernel interfaces, or talking to systemd over a
socket. It's statically linked for the same reason: `/etc/ld.so.preload` is
itself a persistence mechanism.

**It cannot see past a kernel-level compromise.** A module that hides itself
defeats userspace enumeration by construction. unbidden is useful against the
overwhelming majority of real persistence, which is file-backed, and a clean
report is not proof of a clean host.

Accounts come from `/etc/passwd`, since a static binary has no NSS — an LDAP or
SSSD account with no local trace won't be enumerated.

## Supported

| | | |
| --- | --- | --- |
| Debian | 12, 13 | dpkg |
| Ubuntu | 22.04, 24.04 | dpkg, snap |
| Linux Mint | 21.x, LMDE | dpkg, Cinnamon |
| Fedora | current, current-1 | rpm (sqlite) |

Everything else runs best-effort. With no package database it reports
provenance as unknown rather than calling every file unpackaged.

Mint 22.x isn't in the matrix: no image exists that is genuinely Mint 22, and
it's Ubuntu noble underneath with Cinnamon on top — both already covered.

## Testing

`cargo test` is unit tests plus a golden record of a whole scan and a mutation
pass that takes a synthetic tree apart 120 ways. CI runs the packaging checks
against eight real distro images, boots actual GNOME and Cinnamon sessions, and
fuzzes the five parsers.

The real one is `ci/vm-harness.sh`, which boots a throwaway VM, installs
[PANIX](https://github.com/Aegrah/PANIX), and for each of its persistence
mechanisms does plant → scan → assert → revert → assert the diff is clean. That
last step is the one that catches a tool reporting things that aren't there
any more.

## Licence

MIT.
