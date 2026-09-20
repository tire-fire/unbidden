use crate::entry::Entry;
use crate::scan::{Collector, Ctx};

pub struct Deep;

impl Collector for Deep {
    fn name(&self) -> &'static str {
        "deep"
    }

    fn collect(&self, _cx: &mut Ctx) -> Vec<Entry> {
        Vec::new()
    }
}
