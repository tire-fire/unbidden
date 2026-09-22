//! §13: an update-motd.d script.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::initscripts;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/update-motd.d/50-fuzz", Box::new(initscripts::InitScripts), data);
});
