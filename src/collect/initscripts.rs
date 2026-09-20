use crate::entry::Entry;
use crate::scan::{Collector, Ctx};

pub struct InitScripts;

impl Collector for InitScripts {
    fn name(&self) -> &'static str {
        "initscripts"
    }

    fn collect(&self, _cx: &mut Ctx) -> Vec<Entry> {
        Vec::new()
    }
}
