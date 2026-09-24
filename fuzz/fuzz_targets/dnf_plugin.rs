//! §13: a dnf plugin configuration.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::pkg;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/dnf/plugins/fuzz.conf", Box::new(pkg::PkgHooks), data);
});
