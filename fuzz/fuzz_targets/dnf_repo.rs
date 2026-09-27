//! §13: a dnf .repo file, with the key files it names.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::sources;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/yum.repos.d/x.repo", Box::new(sources::Sources), data);
});
