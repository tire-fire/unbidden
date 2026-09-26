//! §13: a polkit pkla file, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::polkit;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/polkit-1/localauthority/50-local.d/fuzz.pkla", &[DAEMON], Box::new(polkit::Polkit), false, data);
});

/// A daemon the collector recognises, or it reads nothing.
const DAEMON: (&str, &[u8]) = ("usr/lib/polkit-1/polkitd", b"polkitbackendlocalauthority");
