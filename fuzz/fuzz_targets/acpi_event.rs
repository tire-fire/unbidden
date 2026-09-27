//! §13: an acpid rule file in /etc/acpi/events.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::events;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/acpi/events/powerbtn", Box::new(events::Events), data);
});
