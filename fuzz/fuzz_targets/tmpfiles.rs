//! §13: a tmpfiles.d file, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::systemd;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/tmpfiles.d/fuzz.conf", Box::new(systemd::Systemd), data);
});
