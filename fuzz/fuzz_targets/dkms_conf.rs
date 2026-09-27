//! §13: dkms.conf: the hook variables dkms sources.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::initramfs;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("usr/src/x-1.0/dkms.conf", &[("usr/sbin/dkms", b"")], Box::new(initramfs::Initramfs), false, data);
});
