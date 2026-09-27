//! §13: a dracut.conf.d file: install_items and module lines.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::initramfs;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/dracut.conf.d/x.conf", &[("usr/bin/dracut", b"")], Box::new(initramfs::Initramfs), false, data);
});
