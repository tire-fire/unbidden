//! Every ATT&CK technique that can mean persistence on Linux has a recorded
//! answer: the kinds that report it, a decision that puts it out of scope,
//! or a gap. A new ATT&CK release's techniques arrive as rows without one
//! (ci/attack-list.py) and fail here until answered.

use unbidden::entry::Kind;

#[test]
fn every_attack_technique_has_an_answer() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ci/attack-coverage.tsv")).unwrap();
    let mut ids = std::collections::BTreeSet::new();
    let mut rows = 0;
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.starts_with("technique\t") && !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(cols.len(), 6, "six columns: {line}");
        let (id, answer, notes) = (cols[0], cols[4].trim(), cols[5].trim());
        assert!(ids.insert(id.to_string()), "{id} listed twice");
        assert!(id.starts_with('T'), "{line}");
        if let Some(kinds) = answer.strip_prefix("kinds:") {
            let kinds: Vec<&str> = kinds.split(',').map(str::trim).filter(|k| !k.is_empty()).collect();
            assert!(!kinds.is_empty(), "{id}: kinds: names nothing");
            for k in kinds {
                assert!(Kind::parse(k).is_some(), "{id} names a kind that does not exist: {k}");
            }
        } else if answer == "out-of-scope" {
            assert!(!notes.is_empty(), "{id}: out of scope needs its reason");
        } else if answer == "gap" {
            assert!(notes.contains("TODO"), "{id}: a gap points at the TODO");
        } else {
            panic!("{id} has no answer: {answer:?}");
        }
        rows += 1;
    }
    assert!(rows >= 60, "the list is the 63 techniques of ATT&CK 19.2, got {rows}");
}
