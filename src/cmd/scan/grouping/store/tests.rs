//! Tests for the JSONL grouping store: false-positive marks and tombstones,
//! cross-run history upserts, and the soft-failure read rules.

use super::*;
use crate::scanning::result::{FindingType, Result};

fn temp_path(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "dalfox-grouping-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    dir.to_string_lossy().to_string()
}

fn finding(param: &str) -> Result {
    let mut r = Result::builder(FindingType::Reflected)
        .data(format!("https://a.test/p?{param}=1"))
        .param(param)
        .payload("<svg>")
        .build();
    r.location = "Query".to_string();
    r
}

#[test]
fn missing_file_opens_clean_and_writes_header_on_first_mark() {
    let path = temp_path("missing");
    let store = GroupingStore::open(&path);
    assert!(store.is_active());
    assert_eq!(store.corrupt_lines, 0);

    append_false_positive(&path, "entry-1", Some("triaged 2026-11-22")).unwrap();
    let reloaded = GroupingStore::open(&path);
    assert!(reloaded.is_false_positive("entry-1"));
    assert_eq!(reloaded.fp_note("entry-1"), Some("triaged 2026-11-22"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn tombstone_clears_a_mark_but_keeps_the_row() {
    let path = temp_path("tombstone");
    append_false_positive(&path, "entry-1", None).unwrap();
    let existing = GroupingStore::load_only(&path)
        .unwrap()
        .false_positives
        .get("entry-1")
        .cloned()
        .unwrap();
    append_false_positive_removal(&path, "entry-1", &existing).unwrap();

    let reloaded = GroupingStore::open(&path);
    assert!(!reloaded.is_false_positive("entry-1"));
    // The audit trail is still physically present.
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(raw.contains("\"removed\":true"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn history_preserves_first_seen_and_accumulates_hits() {
    let path = temp_path("history");
    let r = finding("q");

    let first = GroupingStore::open(&path);
    let key = injection_point_key(&r);
    assert!(first.record_observation(&r, "group-1", "https://a.test/p"));
    drop(first);

    let second = GroupingStore::open(&path);
    assert!(second.record_observation(&r, "group-1", "https://a.test/p"));
    drop(second);

    let third = GroupingStore::load_only(&path).unwrap();
    let rec = third.history(&key).expect("history row exists");
    assert_eq!(rec.hit_count, 2);
    assert_eq!(rec.param, "q");
    assert_eq!(rec.location, "Query");
    assert_eq!(rec.endpoint, "https://a.test/p");
    // first_seen must be the older timestamp, last_confirmed the newer one.
    assert!(rec.first_seen <= rec.last_confirmed);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn repeat_hits_are_recorded_at_most_once_per_run() {
    let path = temp_path("once");
    append_false_positive(&path, "entry-1", None).unwrap();
    let store = GroupingStore::open(&path);

    assert!(store.record_fp_repeat_hit("entry-1"));
    // Second call in the same run is a no-op.
    assert!(store.record_fp_repeat_hit("entry-1"));
    drop(store);

    let reloaded = GroupingStore::open(&path);
    assert_eq!(reloaded.fp_repeat_hits("entry-1"), 1);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn torn_final_line_is_skipped_not_fatal() {
    let path = temp_path("torn");
    append_false_positive(&path, "entry-1", None).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{\"kind\":\"history\",\"entry_key\":\"brok")
        .unwrap();

    let store = GroupingStore::open(&path);
    assert!(store.is_active());
    assert_eq!(store.corrupt_lines, 1);
    assert!(store.is_false_positive("entry-1"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn foreign_file_is_rejected_softly() {
    let path = temp_path("foreign");
    std::fs::write(&path, "this is just a target list\nhttps://a.test\n").unwrap();
    let store = GroupingStore::open(&path);
    assert!(!store.is_active());
    assert!(store.warning.is_some());
    // Memory is empty but the process must not crash; grouping still works
    // in-memory for the current run.
    assert!(!store.is_false_positive("anything"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn newer_format_version_is_not_misread() {
    let path = temp_path("version");
    std::fs::write(
        &path,
        "{\"dalfox_grouping\":99,\"version\":\"9.9.9\",\"created\":\"x\"}\n",
    )
    .unwrap();
    let store = GroupingStore::open(&path);
    assert!(!store.is_active());
    assert!(store
        .warning
        .as_deref()
        .unwrap_or("")
        .contains("grouping format"));
    let _ = std::fs::remove_file(&path);
}
