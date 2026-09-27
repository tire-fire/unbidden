//! §13: a Firefox pref file: pref(), lockPref() lines naming autoconfig.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::browsers;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/firefox-esr/syspref.js", &[("usr/lib/firefox-esr/firefox-esr", b"")], Box::new(browsers::Browsers), false, data);
});
