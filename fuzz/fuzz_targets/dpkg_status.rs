//! §13: dpkg's status file, read in enrichment for the package that claims an entry's source.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

const SETUP: &[(&str, &[u8])] = &[
    ("etc/crontab", b"* * * * * root /bin/true\n"),
    ("var/lib/dpkg/info/cron.list", b"/etc/crontab\n"),
    ("var/lib/dpkg/info/cron.md5sums", b"00000000000000000000000000000000  etc/crontab\n"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("var/lib/dpkg/status", SETUP, Box::new(cron::Cron), true, data);
});
