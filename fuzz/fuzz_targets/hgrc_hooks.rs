//! §13: an hgrc: its [hooks] section, continuations, comments.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::vcs;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/mercurial/hgrc", &[("usr/bin/hg", b"")], Box::new(vcs::Vcs), false, data);
});
