use crate::entry::Entry;
use crate::scan::{Collector, Ctx};

pub struct Cron;

impl Collector for Cron {
    fn name(&self) -> &'static str {
        "cron"
    }

    fn collect(&self, _cx: &mut Ctx) -> Vec<Entry> {
        Vec::new()
    }
}
