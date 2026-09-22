//! §13: os-release, read for the header on every scan.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::shell;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/os-release", Box::new(shell::Shell), data);
});
