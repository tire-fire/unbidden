//! §13: an ICD or layer manifest: JSON naming a library_path.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::plugins;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("usr/share/vulkan/implicit_layer.d/x.json", &[("usr/bin/iconv", b"")], Box::new(plugins::Plugins), false, data);
});
