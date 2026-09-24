//! §13: an authorized_keys file, options and all.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::auth;

const SETUP: &[(&str, &[u8])] = &[
    ("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("root/.ssh/authorized_keys", SETUP, Box::new(auth::Auth), false, data);
});
