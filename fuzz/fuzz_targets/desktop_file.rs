//! §13: a .desktop file, as an adversary may have authored it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::desktop;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/xdg/autostart/fuzz.desktop", Box::new(desktop::Desktop), data);
});
