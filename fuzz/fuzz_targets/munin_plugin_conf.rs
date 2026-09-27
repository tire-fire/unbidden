//! §13: munin-node plugin configuration: sections, wildcards, user and command.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::agents;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/munin/plugin-conf.d/x", Box::new(agents::Agents), data);
});
