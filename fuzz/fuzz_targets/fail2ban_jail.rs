//! §13: fail2ban's jail configuration: INI, interpolation, action lists.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::fail2ban;

const SETUP: &[(&str, &[u8])] = &[
    ("usr/bin/fail2ban-server", b""),
    ("etc/fail2ban/action.d/iptables.conf", b"[INCLUDES]\nbefore = common.conf\n[Definition]\nactionban = <iptables> -I <chain> -s <ip> -j <blocktype>\n[Init]\niptables = iptables <lockingopt>\nlockingopt = -w\n"),
];

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_with("etc/fail2ban/jail.conf", SETUP, Box::new(fail2ban::Fail2ban), false, data);
});
