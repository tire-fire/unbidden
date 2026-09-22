//! §13: a udev rule file, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::kernel;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/udev/rules.d/99-fuzz.rules", Box::new(kernel::Kernel), data);
});
