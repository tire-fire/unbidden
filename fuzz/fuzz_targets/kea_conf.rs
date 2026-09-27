//! §13: Kea's JSON: comments, includes, hooks libraries.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::events;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/kea/kea-dhcp4.conf", &[("usr/sbin/kea-dhcp4", b"")], Box::new(events::Events), false, data);
});
