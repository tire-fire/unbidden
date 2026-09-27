//! §13: clamd.conf: Name value lines, quoting, the Example guard.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::events;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/clamav/clamd.conf", &[("usr/sbin/clamd", b"")], Box::new(events::Events), false, data);
});
