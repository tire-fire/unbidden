//! §13: ifupdown's /etc/network/interfaces.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::initscripts;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/network/interfaces", Box::new(initscripts::InitScripts), data);
});
