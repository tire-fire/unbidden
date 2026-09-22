//! §13: a dpkg md5sums manifest, the digests integrity is checked against.
//! The fixed status file declares no conffiles: a conffile is checked against
//! status instead, and the manifest would never be read.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

const SETUP: &[(&str, &[u8])] = &[
    ("etc/crontab", b"* * * * * root /bin/true\n"),
    ("var/lib/dpkg/info/cron.list", b"/etc/crontab\n"),
    ("var/lib/dpkg/status", b"Package: cron\nStatus: install ok installed\nVersion: 3.0\n\n"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("var/lib/dpkg/info/cron.md5sums", SETUP, Box::new(cron::Cron), true, data);
});
