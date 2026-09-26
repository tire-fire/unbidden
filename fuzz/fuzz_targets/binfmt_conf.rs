//! §13: etc/binfmt.d/fuzz.conf, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::kernel;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/binfmt.d/fuzz.conf", Box::new(kernel::Kernel), data);
});
