//! §13: apk's etc/apk/repositories.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::sources;

const SETUP: &[(&str, &[u8])] = &[
    ("lib/apk/db/installed", b"C:Q1tUBevAL33YvpW2JlxUskPVRWq48=\nP:busybox\nV:1.37.0-r31\nF:bin\nR:busybox\nZ:Q1tUBevAL33YvpW2JlxUskPVRWq48=\n\n"),
    ("etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub", b"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n"),
    ("sbin/apk", b"\x7fELF apk"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/apk/repositories", SETUP, Box::new(sources::Sources), false, data);
});
