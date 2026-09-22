//! §13: a modules-load.d list.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::kernel;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/modules-load.d/fuzz.conf", Box::new(kernel::Kernel), data);
});
