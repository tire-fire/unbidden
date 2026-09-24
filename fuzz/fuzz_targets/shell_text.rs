//! §13: shell text an entry runs: a cron command is split into simple commands
//! and followed through wrappers, `sh -c`, `$(...)` and `eval`, all of which
//! any user can nest as deep as they like in their own crontab.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

fuzz_target!(|data: &[u8]| {
    // One cron line: the fuzzed bytes are the command, so a newline in them
    // would end it and start a line the cron parser rejects.
    let mut line = b"* * * * * root ".to_vec();
    line.extend(data.iter().copied().filter(|b| *b != b'\n'));
    line.push(b'\n');
    unbidden_fuzz::feed_with("etc/cron.d/fuzzed", &[], Box::new(cron::Cron), true, &line);
});
