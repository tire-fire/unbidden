//! §13: gconv-modules: module and alias lines.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::plugins;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("usr/lib64/gconv/gconv-modules", &[("usr/bin/iconv", b"")], Box::new(plugins::Plugins), false, data);
});
