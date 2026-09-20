use crate::entry::Entry;
use crate::scan::{Collector, Ctx};

pub struct Systemd;

impl Collector for Systemd {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn collect(&self, _cx: &mut Ctx) -> Vec<Entry> {
        Vec::new()
    }
}
