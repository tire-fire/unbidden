//! §13: pacman's per-package `files` list, read in enrichment for the package that claims an entry's source.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

const SETUP: &[(&str, &[u8])] = &[("etc/crontab", b"* * * * * root /bin/true\n")];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("var/lib/pacman/local/tool-1.0-1/files", SETUP, Box::new(cron::Cron), true, data);
});
