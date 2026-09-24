//! §13: an at job spool file.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("var/spool/cron/atjobs/a0000101a2b3c4", Box::new(cron::Cron), data);
});
