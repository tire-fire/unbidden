//! §13: dpkg's own dpkg.cfg and its invoke hooks.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::pkg;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/dpkg/dpkg.cfg", Box::new(pkg::PkgHooks), data);
});
