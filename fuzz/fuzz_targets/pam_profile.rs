//! §13: a pam-configs profile, parsed and expanded to reproduce the
//! /etc/pam.d/common-auth stack pam-auth-update would write from it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::auth;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("usr/share/pam-configs/unix", SETUP, Box::new(auth::Auth), true, data);
});

const SETUP: &[(&str, &[u8])] = &[
    ("var/lib/pam/auth", b"Module: unix\n"),
    (
        "usr/share/pam/common-auth",
        b"# here are the per-package modules (the \"Primary\" block)\n$auth_primary\n# here's the fallback if no module succeeds\nauth\trequisite\t\t\tpam_deny.so\n# and here are more per-package modules (the \"Additional\" block)\n$auth_additional\n# end of pam-auth-update config\n",
    ),
    ("etc/pam.d/common-auth", b"auth\t[success=1 default=ignore]\tpam_unix.so nullok\n"),
];
