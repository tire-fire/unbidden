//! §13: pacman's per-package `mtree`, a gzip of the build manifest, read for the digest, mode and link target of a path the package owns.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::cron;

const SETUP: &[(&str, &[u8])] = &[
    ("etc/crontab", b"* * * * * root /bin/true\n"),
    ("var/lib/pacman/local/tool-1.0-1/files", b"%FILES%\netc/\netc/crontab\n\n%BACKUP%\netc/crontab\t00000000000000000000000000000000\n"),
];

/// A gzip whose deflate stream is stored blocks, so the fuzzed bytes reach
/// the manifest parser as text instead of failing to inflate.
fn stored_gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    let chunks: Vec<&[u8]> = if data.is_empty() { vec![&[]] } else { data.chunks(0xffff).collect() };
    for (i, chunk) in chunks.iter().enumerate() {
        out.push(u8::from(i + 1 == chunks.len()));
        let len = chunk.len() as u16;
        out.extend(len.to_le_bytes());
        out.extend((!len).to_le_bytes());
        out.extend(*chunk);
    }
    out.extend([0u8; 8]);
    out
}

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_encoded(
        "var/lib/pacman/local/tool-1.0-1/mtree",
        SETUP,
        Box::new(cron::Cron),
        true,
        data,
        |path, bytes| std::fs::write(path, stored_gzip(bytes)).expect("fuzz root is writable"),
    );
});
