//! §13: /etc/environment, read by pam_env as KEY=value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::shell;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/environment", Box::new(shell::Shell), data);
});
