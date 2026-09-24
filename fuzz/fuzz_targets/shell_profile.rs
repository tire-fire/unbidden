//! §13: /etc/profile, sourced by every login shell.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::shell;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/profile", Box::new(shell::Shell), data);
});
