//! §13: wg-quick's interface configuration.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::initscripts;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/wireguard/wg0.conf", Box::new(initscripts::InitScripts), data);
});
