//! §13: a D-Bus activation file.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::pkg;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("usr/share/dbus-1/system-services/org.fuzz.service", Box::new(pkg::PkgHooks), data);
});
