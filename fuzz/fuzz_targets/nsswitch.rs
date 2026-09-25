//! §13: nsswitch.conf, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::auth;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/nsswitch.conf", Box::new(auth::Auth), data);
});
