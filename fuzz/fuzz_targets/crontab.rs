//! §13: a crontab, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/cron.d/fuzz", Box::new(cron::Cron), data);
});
