//! §13: a dpkg file list, the record of which package owns which path.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

const SETUP: &[(&str, &[u8])] = &[
    ("etc/crontab", b"* * * * * root /bin/true\n"),
    ("var/lib/dpkg/status", b"Package: cron\nStatus: install ok installed\nVersion: 3.0\n\n"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("var/lib/dpkg/info/cron.list", SETUP, Box::new(cron::Cron), true, data);
});
