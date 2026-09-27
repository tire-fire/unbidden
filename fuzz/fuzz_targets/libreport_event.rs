//! §13: a libreport events.d file: EVENT= rules and their indented shell.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::events;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/libreport/events.d/x.conf", &[("usr/libexec/abrt-handle-event", b"")], Box::new(events::Events), false, data);
});
