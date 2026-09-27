//! §13: logrotate.conf, its blocks, scripts and includes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::logrotate;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/logrotate.conf", Box::new(logrotate::Logrotate), data);
});
