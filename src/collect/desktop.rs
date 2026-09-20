use crate::entry::Entry;
use crate::scan::{Collector, Ctx};

pub struct Desktop;

impl Collector for Desktop {
    fn name(&self) -> &'static str {
        "desktop"
    }

    fn collect(&self, _cx: &mut Ctx) -> Vec<Entry> {
        Vec::new()
    }
}
