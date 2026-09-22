//! §13: a systemd unit file, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::systemd;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/systemd/system/fuzz.service", Box::new(systemd::Systemd), data);
});
