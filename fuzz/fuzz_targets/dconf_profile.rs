//! §13: the dconf profile naming the database stack.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::desktop;

const SETUP: &[(&str, &[u8])] = &[
    ("etc/passwd", b"fuzz:x:1000:1000::/home/fuzz:/bin/sh\n"),
    ("home/fuzz/.local/share/gnome-shell/extensions/x@y.z/metadata.json", br#"{"uuid":"x@y.z"}"#),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/dconf/profile/user", SETUP, Box::new(desktop::Desktop), false, data);
});
