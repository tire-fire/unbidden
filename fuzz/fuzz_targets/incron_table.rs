//! §13: an incron system table: escaped path and mask, raw command.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::agents;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/incron.d/x", Box::new(agents::Agents), data);
});
