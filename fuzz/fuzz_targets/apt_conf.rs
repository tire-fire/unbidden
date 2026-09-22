//! §13: apt configuration, nested blocks, hooks and all.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::pkg;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/apt/apt.conf.d/99fuzz", Box::new(pkg::PkgHooks), data);
});
