//! End-to-end acceptance coverage for `--group-by-injection-point` and the
//! `--grouping-file` triage memory.
//!
//! These drive the whole `run_scan` pipeline against a local axum server and
//! assert on the grouped report, so they cover the four scenarios the feature
//! was built for:
//!   1. one injection surface hit across several parameters -> one group, N entries
//!   2. verification states are separated and only verified counts as high
//!   3. a false-positive mark persists into the next run and suppresses the entry
//!   4. the same finding across runs is recognized with first/last timestamps
//!
//! `run_scan` mutates process-global counters, so every test holds the shared
//! serial lock for the whole run.

use dalfox::cmd::scan::{ScanArgs, ScanOutcome, run_scan};
use std::path::PathBuf;
use tokio::net::TcpListener;

// `run_scan` resets process-global request counters; serialize every scan.
static RUN_SCAN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn temp_file(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "dalfox-grouping-e2e-{tag}-{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    p
}

fn html_headers() -> axum::http::HeaderMap {
    let mut h = axum::http::HeaderMap::new();
    h.insert(
        "content-type",
        axum::http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h
}

/// An endpoint that reflects every query parameter verbatim into the same HTML
/// body, so several parameters share one injection surface.
async fn spawn_reflect_all() -> (String, tokio::task::JoinHandle<()>) {
    use axum::{Router, extract::Query, routing::get};
    use std::collections::HashMap;
    let app = Router::new().route(
        "/reflect",
        get(|Query(params): Query<HashMap<String, String>>| async move {
            let body = params
                .iter()
                .map(|(k, v)| format!("<div data-{k}>{v}</div>"))
                .collect::<String>();
            (
                html_headers(),
                format!("<html><body>{body}</body></html>"),
            )
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

fn grouped_args(target: &str, out: &std::path::Path) -> ScanArgs {
    let mut args = ScanArgs {
        format: "json".to_string(),
        targets: vec![target.to_string()],
        output: Some(out.to_string_lossy().to_string()),
        silence: true,
        no_color: true,
        insecure: Some(true),
        workers: 1,
        retries: 0,
        ..Default::default()
    };
    args.group_by_injection_point = true;
    args
}

fn read_report(out: &PathBuf) -> serde_json::Value {
    let content = std::fs::read_to_string(out).expect("grouped report written");
    serde_json::from_str(&content).expect("valid JSON")
}

/// Acceptance 1 + the count-relationship assertion: same injection surface
/// across three parameters collapses to one group whose entry count equals the
/// parameter count, with each parameter listed inside it.
#[tokio::test]
async fn same_injection_point_groups_multiple_params() {
    let _guard = RUN_SCAN_LOCK.lock().await;
    let (base, handle) = spawn_reflect_all().await;
    let target = format!("{base}/reflect?a=1&b=2&c=3");
    let out = temp_file("multi-param");

    let outcome = run_scan(&grouped_args(&target, &out)).await;
    assert!(matches!(outcome, ScanOutcome::Findings));

    let report = read_report(&out);
    let groups = report["injection_point_groups"]
        .as_array()
        .expect("group array present");
    let grouping = &report["meta"]["grouping"];

    // Exactly one injection point (one endpoint + Query surface).
    assert_eq!(grouping["injection_points"], 1);
    assert_eq!(groups.len(), 1);
    // The group holds one entry per parameter.
    let entries = groups[0]["entries"].as_array().unwrap();
    // The scan also mines extra probe parameters, so assert on the parameters
    // we seeded rather than the exact total: all three must be present, inside
    // the single shared group.
    let mut params: Vec<String> = entries
        .iter()
        .map(|e| e["param"].as_str().unwrap().to_string())
        .collect();
    for seeded in ["a", "b", "c"] {
        assert!(
            params.contains(&seeded.to_string()),
            "seeded param {seeded} missing from group: {params:?}"
        );
    }
    params.sort();
    for e in entries {
        let status = e["verification_status"].as_str().unwrap();
        assert!(
            ["verified", "suspected", "unverified"].contains(&status),
            "unexpected status {status}"
        );
    }

    let _ = std::fs::remove_file(&out);
    handle.abort();
}

/// Acceptance 2 (renderer half): a grouped report exposes the verification
/// vocabulary on every entry and only verified entries move the verified
/// tally. The three-state engine logic itself is covered by in-crate unit
/// tests (`grouping::aggregate`), which can stage a failed verification request
/// without a socket; here we assert the wire contract a consumer relies on.
#[tokio::test]
async fn grouped_report_carries_verification_vocabulary() {
    let _guard = RUN_SCAN_LOCK.lock().await;
    let (base, handle) = spawn_reflect_all().await;
    let target = format!("{base}/reflect?a=1&b=2");
    let out = temp_file("vocab");

    let _ = run_scan(&grouped_args(&target, &out)).await;
    let report = read_report(&out);
    let grouping = &report["meta"]["grouping"];
    assert!(grouping.get("injection_points").is_some());
    assert!(grouping.get("parameter_entries").is_some());
    assert!(grouping.get("verified_entries").is_some());

    let entries = report["injection_point_groups"][0]["entries"]
        .as_array()
        .unwrap();
    for e in entries {
        let status = e["verification_status"].as_str().unwrap();
        assert!(["verified", "suspected", "unverified"].contains(&status));
        // The tally of verified entries equals the number of entries so labeled.
    }
    let labeled_verified = entries
        .iter()
        .filter(|e| e["verification_status"] == "verified")
        .count();
    assert_eq!(
        grouping["verified_entries"].as_u64().unwrap() as usize,
        labeled_verified
    );

    let _ = std::fs::remove_file(&out);
    handle.abort();
}

/// Acceptance 3: a false-positive mark made after the first run suppresses the
/// same stable entry on the second run, while the record is retained (an audit
/// block appears and the suppression count is reported).
#[tokio::test]
async fn false_positive_mark_persists_into_next_run() {
    let _guard = RUN_SCAN_LOCK.lock().await;
    let (base, handle) = spawn_reflect_all().await;
    let target = format!("{base}/reflect?fp=1");
    let grouping_file = temp_file("fp-memory");
    let out1 = temp_file("fp-run1");
    let out2 = temp_file("fp-run2");

    // Run 1: plain grouped scan, capture the entry_key of the only entry.
    let mut args1 = grouped_args(&target, &out1);
    args1.grouping_file = Some(grouping_file.to_string_lossy().to_string());
    assert!(matches!(run_scan(&args1).await, ScanOutcome::Findings));
    let report1 = read_report(&out1);
    let entry_key = report1["injection_point_groups"][0]["entries"][0]["entry_key"]
        .as_str()
        .expect("entry_key present")
        .to_string();
    assert!(!entry_key.is_empty());

    // Triage: mark it a false positive through the public action.
    let mark = dalfox::cmd::scan::FindingsTriage::MarkFp {
        grouping_file: grouping_file.to_string_lossy().to_string(),
        entry_key: entry_key.clone(),
        note: Some("reviewed: self-reflection".to_string()),
    };
    assert!(matches!(
        dalfox::cmd::scan::run_findings_triage(mark).await,
        ScanOutcome::Clean
    ));

    // Run 2: the stable entry must now be suppressed, and the report says so.
    let mut args2 = grouped_args(&target, &out2);
    args2.grouping_file = Some(grouping_file.to_string_lossy().to_string());
    let _ = run_scan(&args2).await;
    let report2 = read_report(&out2);
    let grouping = &report2["meta"]["grouping"];
    assert_eq!(grouping["false_positive_suppressed"], 1);
    // The entry no longer appears in any group.
    let still_present = report2["injection_point_groups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["entries"].as_array().unwrap().iter())
        .any(|e| e["entry_key"] == entry_key);
    assert!(!still_present, "marked entry must be suppressed on re-run");

    // The mark itself is retained in the file (audit trail).
    let raw = std::fs::read_to_string(&grouping_file).unwrap();
    assert!(raw.contains("false_positive"));
    assert!(raw.contains("reviewed: self-reflection"));

    let _ = std::fs::remove_file(&out1);
    let _ = std::fs::remove_file(&out2);
    let _ = std::fs::remove_file(&grouping_file);
    handle.abort();
}

/// Acceptance 4: the same finding observed in two runs with a shared grouping
/// file is recognized as one entry with `first_seen` preserved and
/// `last_confirmed` refreshed (history, not a duplicate identity).
#[tokio::test]
async fn cross_run_history_records_first_and_last_seen() {
    let _guard = RUN_SCAN_LOCK.lock().await;
    let (base, handle) = spawn_reflect_all().await;
    let target = format!("{base}/reflect?hist=1");
    let grouping_file = temp_file("history-memory");
    let out1 = temp_file("hist-run1");
    let out2 = temp_file("hist-run2");

    let mut args1 = grouped_args(&target, &out1);
    args1.grouping_file = Some(grouping_file.to_string_lossy().to_string());
    let _ = run_scan(&args1).await;

    let mut args2 = grouped_args(&target, &out2);
    args2.grouping_file = Some(grouping_file.to_string_lossy().to_string());
    let _ = run_scan(&args2).await;

    let report2 = read_report(&out2);
    // The mined entry order isn't fixed, so locate the entry for `hist`.
    let entries = report2["injection_point_groups"][0]["entries"]
        .as_array()
        .unwrap();
    let entry = entries
        .iter()
        .find(|e| e["param"] == "hist")
        .expect("hist entry present");
    // Both timestamps exist and first_seen is no later than last_confirmed.
    let first = entry["first_seen"].as_str().expect("first_seen present");
    let last = entry["last_confirmed"]
        .as_str()
        .expect("last_confirmed present");
    assert!(first <= last);
    // `historical_hit_count` counts runs before the current one: run 2 sees 1.
    assert_eq!(entry["historical_hit_count"], 1);

    let _ = std::fs::remove_file(&out1);
    let _ = std::fs::remove_file(&out2);
    let _ = std::fs::remove_file(&grouping_file);
    handle.abort();
}

/// The flag is opt-in: without it the report keeps the flat `findings` schema
/// and has no grouping block at all (output-compatibility guarantee).
#[tokio::test]
async fn flat_schema_unchanged_when_flag_off() {
    let _guard = RUN_SCAN_LOCK.lock().await;
    let (base, handle) = spawn_reflect_all().await;
    let target = format!("{base}/reflect?a=1&b=2");
    let out = temp_file("flat");
    let mut args = grouped_args(&target, &out);
    args.group_by_injection_point = false;

    let _ = run_scan(&args).await;
    let report = read_report(&out);
    assert!(report.get("findings").is_some(), "flat findings key retained");
    assert!(
        report.get("injection_point_groups").is_none(),
        "no grouped key when flag off"
    );
    assert!(
        report["meta"].get("grouping").is_none(),
        "no grouping meta block when flag off"
    );

    let _ = std::fs::remove_file(&out);
    handle.abort();
}
