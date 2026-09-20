use crate::entry::Entry;
use crate::scan::{Collector, Ctx};

pub struct Auth;

impl Collector for Auth {
    fn name(&self) -> &'static str {
        "auth"
    }

    fn collect(&self, _cx: &mut Ctx) -> Vec<Entry> {
        Vec::new()
    }
}
