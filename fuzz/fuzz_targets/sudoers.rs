//! §13: sudoers, with its aliases, tags and include lines.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::auth;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/sudoers", Box::new(auth::Auth), data);
});
