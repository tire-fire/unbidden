//! §13: /etc/passwd, the only account database a static binary has.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::shell;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/passwd", Box::new(shell::Shell), data);
});
