use crate::entry::Entry;
use crate::scan::{Collector, Ctx};

pub struct Kernel;

impl Collector for Kernel {
    fn name(&self) -> &'static str {
        "kernel"
    }

    fn collect(&self, _cx: &mut Ctx) -> Vec<Entry> {
        Vec::new()
    }
}
