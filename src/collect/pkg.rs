use crate::entry::Entry;
use crate::scan::{Collector, Ctx};

pub struct PkgHooks;

impl Collector for PkgHooks {
    fn name(&self) -> &'static str {
        "pkg"
    }

    fn collect(&self, _cx: &mut Ctx) -> Vec<Entry> {
        Vec::new()
    }
}
