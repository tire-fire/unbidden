//! §13: /etc/crypttab and its keyscript= options.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::initscripts;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/crypttab", Box::new(initscripts::InitScripts), data);
});
