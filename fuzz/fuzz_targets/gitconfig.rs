//! §13: a git configuration, whose pager, editor and hooks path run programs.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::deep;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/gitconfig", Box::new(deep::GitConfig), data);
});
