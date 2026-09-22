# unbidden

Finds what runs automatically on Linux.

[![ci](https://github.com/tire-fire/unbidden/actions/workflows/ci.yml/badge.svg)](https://github.com/tire-fire/unbidden/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/unbidden.svg)](https://crates.io/crates/unbidden)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![unbidden finding planted persistence on a Debian host](docs/scan.svg)

systemd units and timers, cron and at, udev rules, PAM, sudoers, SSH keys, XDG
autostart, GNOME and Cinnamon extensions, package manager hooks, shell startup
files, rc.local, SysV init. If it runs without a person typing something, it
should turn up here.

Most of what turns up is noise. A desktop has well over a thousand autostart
entries, nearly all of them from a package and untouched since. unbidden reads
the dpkg and rpm databases itself and hides those, so you get the short list:
1,690 hidden on the host in the screenshot.

## Install

The binaries in [releases](https://github.com/tire-fire/unbidden/releases) are
musl, so they're static and they'll run on anything from RHEL 7 to Alpine
without installing a thing first.

```sh
cargo install unbidden
```

works too, but it links against your system libc. For a static one, build it
against musl:

```sh
rustup target add x86_64-unknown-linux-musl
cargo install unbidden --target x86_64-unknown-linux-musl
```

## Use

```sh
unbidden                          # the short list
unbidden --all --json             # everything, one record per line
unbidden --flag unpackaged        # also packaged-modified, world-writable, ...
unbidden --kind cron --trigger login
unbidden --deep                   # adds SUID, file caps, git hooks (walks the disk)
unbidden --save base.json         # and later:
unbidden --against base.json      # what changed?
unbidden explain 8f4e03c59dff     # one entry in full, with the text it came from
```

An entry's id doesn't move when the entry's contents do. A backdoor that
rewrites its own `ExecStart` shows up as one changed row telling you which
fields moved, instead of a removal and an addition you have to notice are the
same thing.

## Limits

It doesn't execute anything on the host it scans. `rpm`, `dpkg` and
`systemctl` are binaries an attacker can replace, so everything here comes from
reading files and kernel interfaces, or from talking to systemd over a socket.
Same reason the released binaries are static: `/etc/ld.so.preload` is a
persistence mechanism in its own right, and a dynamically linked scanner loads
whatever it says before `main()`.

Kernel-level compromise is out of scope. A module that unlinks itself isn't
visible to anything running in userspace, this included. unbidden covers
file-backed persistence, so a clean report isn't the same as a clean machine.

Accounts come out of `/etc/passwd`, because a static binary has no NSS. An LDAP
or SSSD account with nothing on local disk won't be picked up.

## Supported

| Distro | Versions | Package database | Extras |
| --- | --- | --- | --- |
| Debian | 12, 13 | dpkg | |
| Ubuntu | 22.04, 24.04 | dpkg | snap |
| Linux Mint | 21.x, LMDE | dpkg | Cinnamon |
| Fedora | current, current-1 | rpm (sqlite) | |

Anything else works on a best-effort basis. With no package database it reports
provenance as unknown rather than calling every file on the box unpackaged.

Mint 22.x isn't tested. Nobody publishes an image that's actually Mint 22, and
underneath it's Ubuntu noble with Cinnamon on top. Both are already covered.

## Testing

`cargo test` covers the collectors, a golden record of a full scan, and a
mutation pass that takes a synthetic tree apart 120 ways. CI runs the packaging
checks against eight distro images, boots real GNOME and Cinnamon sessions, and
fuzzes the parsers. `ci/vm-harness.sh` boots a throwaway VM and plants every
mechanism [PANIX](https://github.com/Aegrah/PANIX) supports, checking that each
one is reported, and that it stops being reported once reverted.

## License

MIT.
