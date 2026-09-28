//! §13: a user crontab as BusyBox's crond reads it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

const SETUP: &[(&str, &[u8])] = &[
    ("bin/busybox", b"\x7fELF BusyBox v1.37.0 multi-call binary"),
    ("usr/sbin/crond", b"\x7fELF BusyBox v1.37.0 multi-call binary"),
    ("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n"),
    ("etc/conf.d/crond", b"CRON_OPTS=\"-c /etc/crontabs\"\n"),
    ("etc/periodic/daily/job", b"#!/bin/sh\n"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/crontabs/root", SETUP, Box::new(cron::Cron), false, data);
});
