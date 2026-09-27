//! §13: a libdnf5 actions file: five colon-separated fields per line.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::pkg;

const SETUP: &[(&str, &[u8])] = &[
    ("etc/dnf/libdnf5-plugins/actions.conf", b"[main]\nname = actions\nenabled = 1\n"),
    ("usr/lib64/libdnf5/plugins/actions.so", b"\x7fELF"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/dnf/libdnf5-plugins/actions.d/10-x.actions", SETUP, Box::new(pkg::PkgHooks), false, data);
});
