//! §13: zabbix_agentd.conf: Parameter=value lines, Include, UserParameter, AllowKey.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::agents;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/zabbix/zabbix_agentd.conf", Box::new(agents::Agents), data);
});
