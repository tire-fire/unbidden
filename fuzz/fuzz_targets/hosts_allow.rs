//! §13: TCP-wrapper rules in hosts.allow.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::inetd;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/hosts.allow", Box::new(inetd::Inetd), data);
});
