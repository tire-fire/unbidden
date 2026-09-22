//! §13: an sshd_config, whose ForceCommand and Match blocks run commands.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::auth;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/ssh/sshd_config", Box::new(auth::Auth), data);
});
