//! §13: an ld.so.conf drop-in, as an adversary may have authored it, read
//! through the include in /etc/ld.so.conf the way ldconfig reaches it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::shell;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/ld.so.conf.d/fuzz.conf", SETUP, Box::new(shell::Shell), true, data);
});

/// The include that reaches the fuzzed file. Enrichment runs, because the
/// writable-search-path check stats every directory the file names.
const SETUP: &[(&str, &[u8])] = &[("etc/ld.so.conf", b"include /etc/ld.so.conf.d/*.conf\n")];
