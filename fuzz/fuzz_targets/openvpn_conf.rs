//! §13: an OpenVPN configuration and the scripts it names.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::initscripts;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/openvpn/client/x.conf", Box::new(initscripts::InitScripts), data);
});
