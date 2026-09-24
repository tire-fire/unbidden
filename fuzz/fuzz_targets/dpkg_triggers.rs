//! §13: a dpkg triggers file, read beside the postinst it wakes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::pkg;

const SETUP: &[(&str, &[u8])] = &[
    ("var/lib/dpkg/info/fuzz.postinst", b"#!/bin/sh\n"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("var/lib/dpkg/info/fuzz.triggers", SETUP, Box::new(pkg::PkgHooks), false, data);
});
