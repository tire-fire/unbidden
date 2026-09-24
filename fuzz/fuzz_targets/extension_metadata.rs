//! §13: an extension's metadata.json, written by the user who installed it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::desktop;

const SETUP: &[(&str, &[u8])] = &[
    ("etc/passwd", b"fuzz:x:1000:1000::/home/fuzz:/bin/sh\n"),
    ("home/fuzz/.local/share/gnome-shell/extensions/x@y.z/extension.js", b""),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("home/fuzz/.local/share/gnome-shell/extensions/x@y.z/metadata.json", SETUP, Box::new(desktop::Desktop), false, data);
});
