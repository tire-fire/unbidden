//! §13: facter.conf: the HOCON keys external-dir and no-external-facts.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::agents;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/facter/facter.conf", Box::new(agents::Agents), data);
});
