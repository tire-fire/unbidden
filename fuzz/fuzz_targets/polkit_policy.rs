//! §13: a polkit policy file, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::polkit;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("usr/share/polkit-1/actions/org.fuzz.policy", &[DAEMON], Box::new(polkit::Polkit), false, data);
});

/// A daemon the collector recognises, or it reads nothing.
const DAEMON: (&str, &[u8]) = ("usr/lib/polkit-1/polkitd", b"polkit._runRules");
