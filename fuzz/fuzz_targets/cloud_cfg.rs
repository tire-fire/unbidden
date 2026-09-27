//! §13: cloud-init's cloud.cfg, through the YAML reader and the merge.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cloudinit;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/cloud/cloud.cfg", Box::new(cloudinit::CloudInit), data);
});
