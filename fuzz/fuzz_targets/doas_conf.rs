//! §13: doas.conf, with its quotes, escapes and continuations.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::auth;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/doas.conf", Box::new(auth::Auth), data);
});
