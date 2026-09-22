//! §13: a script an entry runs: enrichment reads its interpreter line and what it hands control to.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

const SETUP: &[(&str, &[u8])] = &[
    ("etc/cron.d/job", b"* * * * * root /usr/local/bin/fuzzed\n"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("usr/local/bin/fuzzed", SETUP, Box::new(cron::Cron), true, data);
});
