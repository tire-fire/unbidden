//! §13: monitrc: its tokens, include, and the programs it runs.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::agents;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/monit/monitrc", Box::new(agents::Agents), data);
});
