//! §13: pam_env.conf, with its DEFAULT and OVERRIDE forms.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::shell;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/security/pam_env.conf", Box::new(shell::Shell), data);
});
