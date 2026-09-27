//! §13: LightDM's lightdm.conf, through the display-manager INI reader.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::dm;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed("etc/lightdm/lightdm.conf", Box::new(dm::DisplayManager), data);
});
