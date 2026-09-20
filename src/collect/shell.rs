use crate::entry::Entry;
use crate::scan::{Collector, Ctx};

pub struct Shell;

impl Collector for Shell {
    fn name(&self) -> &'static str {
        "shell"
    }

    fn collect(&self, _cx: &mut Ctx) -> Vec<Entry> {
        Vec::new()
    }
}
