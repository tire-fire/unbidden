//! §13: a SysV init script and its LSB header.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::initscripts;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/init.d/fuzz", Box::new(initscripts::InitScripts), data);
});
