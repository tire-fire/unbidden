//! §13: an rpm package header, the record the rpm backend parses for file
//! ownership, digests, link targets, scriptlets and file triggers.
//!
//! The input is one header blob. It is wrapped in a real sqlite rpmdb, the
//! way rpm stores it, so what is fuzzed is the header parser and not
//! SQLite's own file-format handling.
#![no_main]

use libfuzzer_sys::fuzz_target;
use unbidden::collect::pkg;

fuzz_target!(|data: &[u8]| {
    unbidden_fuzz::feed_encoded(
        "var/lib/rpm/rpmdb.sqlite",
        &[("etc/crontab", b"* * * * * root /bin/true\n")],
        Box::new(pkg::PkgHooks),
        true,
        data,
        |path, blob| {
            let _ = std::fs::remove_file(path);
            let conn = rusqlite::Connection::open(path).expect("fuzz root is writable");
            conn.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL)", [])
                .expect("schema");
            conn.execute("INSERT INTO Packages (hnum, blob) VALUES (1, ?1)", [blob]).expect("insert");
        },
    );
});
