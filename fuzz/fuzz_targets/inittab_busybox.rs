//! §13: /etc/inittab as BusyBox's init reads it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::inittab;

const SETUP: &[(&str, &[u8])] = &[("sbin/init", b"\x7fELF BusyBox v1.37.0 multi-call binary /etc/inittab")];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/inittab", SETUP, Box::new(inittab::Inittab), false, data);
});
