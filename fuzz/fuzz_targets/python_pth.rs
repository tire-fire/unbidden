//! §13: Python .pth files in a site-packages directory.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::python;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("usr/lib/python3.12/site-packages/x.pth", Box::new(python::Python), data);
});
