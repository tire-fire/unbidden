//! §13: auditd plugin configuration: key = value lines, active, path, args.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::agents;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/audit/plugins.d/x.conf", Box::new(agents::Agents), data);
});
