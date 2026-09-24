//! §13: rc.local.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::initscripts;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/rc.local", Box::new(initscripts::InitScripts), data);
});
