//! §13: an xinetd service file, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::inetd;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/xinetd.d/fuzz", SETUP, Box::new(inetd::Inetd), false, data);
});

/// The daemon, or nothing is read; and the file that includes the fuzzed one.
const SETUP: &[(&str, &[u8])] = &[("usr/sbin/xinetd", b""), ("etc/xinetd.conf", b"includedir /etc/xinetd.d\n")];
