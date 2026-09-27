//! §13: a SpamAssassin .cf file: loadplugin lines.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::events;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/spamassassin/local.cf", &[("usr/sbin/spamd", b"")], Box::new(events::Events), false, data);
});
