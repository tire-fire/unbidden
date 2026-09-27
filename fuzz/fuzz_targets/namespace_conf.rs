//! §13: pam_namespace's namespace.conf, with its quotes and method flags.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::auth;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/security/namespace.conf", Box::new(auth::Auth), data);
});
