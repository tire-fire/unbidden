//! §13: /etc/inetd.conf, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::inetd;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/inetd.conf", SETUP, Box::new(inetd::Inetd), false, data);
});

/// The daemon, or nothing is read.
const SETUP: &[(&str, &[u8])] = &[("usr/sbin/inetd", b"")];
