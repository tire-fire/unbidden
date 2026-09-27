//! §13: tmux.conf: words, quotes, continuations, run-shell and hooks.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::editors;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/tmux.conf", &[("usr/bin/tmux", b"")], Box::new(editors::Editors), false, data);
});
