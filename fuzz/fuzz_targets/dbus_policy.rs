//! §13: a D-Bus policy file, read to annotate the service it names.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::pkg;

const SETUP: &[(&str, &[u8])] = &[
    ("usr/share/dbus-1/system-services/org.fuzz.service", b"[D-BUS Service]\nName=org.fuzz\nExec=/bin/true\nUser=root\n"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/dbus-1/system.d/org.fuzz.conf", SETUP, Box::new(pkg::PkgHooks), false, data);
});
