//! §13: /etc/ld.so.preload, and the preload entries enrichment builds from it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::shell;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/ld.so.preload", &[], Box::new(shell::Shell), true, data);
});
