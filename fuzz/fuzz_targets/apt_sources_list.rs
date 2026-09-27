//! §13: the one-line apt sources.list, with the key files it names.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::sources;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/apt/sources.list", Box::new(sources::Sources), data);
});
