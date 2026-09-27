//! §13: nrpe.cfg: name=value lines, includes, command[], command_prefix.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::agents;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/nagios/nrpe.cfg", Box::new(agents::Agents), data);
});
