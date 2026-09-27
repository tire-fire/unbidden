//! §13: dpkg's diversions database.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::pkg;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("var/lib/dpkg/diversions", Box::new(pkg::PkgHooks), data);
});
