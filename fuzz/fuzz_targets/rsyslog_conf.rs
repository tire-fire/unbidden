//! §13: rsyslog.conf, its includes and the programs its actions run.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::events;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/rsyslog.conf", Box::new(events::Events), data);
});
