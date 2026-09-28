//! §13: /etc/inittab as sysvinit's init reads it, with inittab.d beside it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::inittab;

const SETUP: &[(&str, &[u8])] = &[
    ("sbin/init", b"\x7fELF init /etc/inittab /etc/inittab.d"),
    ("etc/inittab.d/10-a.tab", b"# a\nsv:2:respawn:/opt/sv\n"),
    ("etc/initscript", b"#!/bin/sh\neval exec \"$4\"\n"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/inittab", SETUP, Box::new(inittab::Inittab), false, data);
});
