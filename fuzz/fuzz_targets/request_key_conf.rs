//! §13: etc/request-key.d/fuzz.conf, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::kernel;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/request-key.d/fuzz.conf", Box::new(kernel::Kernel), data);
});
