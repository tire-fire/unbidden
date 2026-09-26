//! §13: an authselect profile template, rendered to reproduce the
//! /etc/pam.d/system-auth authselect would write from it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::auth;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("usr/share/authselect/default/local/system-auth", SETUP, Box::new(auth::Auth), true, data);
});

const SETUP: &[(&str, &[u8])] = &[
    ("etc/authselect/authselect.conf", b"local\nwith-silent-lastlog\nwith-faillock\n"),
    ("etc/pam.d/system-auth", b"auth        required                                     pam_env.so\n"),
];
