//! §13: screenrc: exec, shell, screen lines with flags.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::editors;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/screenrc", &[("usr/bin/screen", b"")], Box::new(editors::Editors), false, data);
});
