//! §13: anacrontab.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/anacrontab", Box::new(cron::Cron), data);
});
