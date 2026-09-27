//! §13: an update-alternatives registration.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::pkg;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("var/lib/dpkg/alternatives/editor", Box::new(pkg::PkgHooks), data);
});
