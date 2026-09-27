//! §13: a cron-apt action file: comments cut, each line apt-get's arguments.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::events;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/cron-apt/action.d/3-download", &[("usr/sbin/cron-apt", b"")], Box::new(events::Events), false, data);
});
