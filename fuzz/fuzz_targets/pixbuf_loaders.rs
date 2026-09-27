//! §13: gdk-pixbuf loaders.cache: quoted stanzas.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::plugins;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("usr/lib64/gdk-pixbuf-2.0/2.10.0/loaders.cache", &[("usr/bin/true", b"")], Box::new(plugins::Plugins), false, data);
});
