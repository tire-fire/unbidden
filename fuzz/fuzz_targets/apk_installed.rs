//! §13: apk's installed database, read in enrichment for the package that claims an entry's source.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

const SETUP: &[(&str, &[u8])] = &[
    ("etc/crontab", b"* * * * * root /bin/true\n"),
    ("etc/apk/protected_paths.d/site.list", b"+etc\n@etc/init.d\n-etc/cron*\n"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("lib/apk/db/installed", SETUP, Box::new(cron::Cron), true, data);
});
