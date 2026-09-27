//! §13: collectd.conf: its grammar, Include, and the exec, python, perl and lua plugins.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::agents;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/collectd/collectd.conf", Box::new(agents::Agents), data);
});
