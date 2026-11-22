//! Renderer tests: the grouped JSON envelope carries the verification labels,
//! the retained failure reason, and the summary counts the engine produced.

use super::*;
use crate::scanning::result::{FindingType, Result, VerifyFailure};

fn finding(tier: FindingType, param: &str) -> Result {
    let mut r = Result::builder(tier)
        .data(format!("https://a.test/p?{param}=1"))
        .param(param)
        .payload("<svg>")
        .build();
    r.location = "Query".to_string();
    r
}

fn three_state_findings() -> Vec<Result> {
    let mut broken = finding(FindingType::Reflected, "broken");
    broken.verify_failure = Some(VerifyFailure {
        reason: "verification request failed: no response after retries".to_string(),
        status: 0,
    });
    vec![
        finding(FindingType::Verified, "ok"),
        finding(FindingType::Reflected, "maybe"),
        broken,
    ]
}

fn empty_meta() -> crate::scanning::result::ScanMetadata {
    crate::scanning::result::ScanMetadata::default()
}

#[test]
fn json_envelope_labels_each_state_and_keeps_failure_reason() {
    let report = crate::cmd::scan::grouping::aggregate(three_state_findings(), None);
    let json = grouped_json_envelope(&report, &empty_meta(), false, false, None);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    let entries = value["injection_point_groups"][0]["entries"]
        .as_array()
        .unwrap();
    let by_param: std::collections::HashMap<&str, &str> = entries
        .iter()
        .map(|e| (e["param"].as_str().unwrap(), e["verification_status"].as_str().unwrap()))
        .collect();
    assert_eq!(by_param["ok"], "verified");
    assert_eq!(by_param["maybe"], "suspected");
    assert_eq!(by_param["broken"], "unverified");

    let broken = entries
        .iter()
        .find(|e| e["param"] == "broken")
        .unwrap();
    assert!(
        broken["verification_reason"]
            .as_str()
            .unwrap()
            .contains("no response")
    );
    assert_eq!(value["meta"]["grouping"]["verified_entries"], 1);
    assert_eq!(value["meta"]["grouping"]["parameter_entries"], 3);
    assert_eq!(value["meta"]["grouping"]["injection_points"], 1);
}

#[test]
fn jsonl_emits_one_group_per_line_plus_meta() {
    let report = crate::cmd::scan::grouping::aggregate(three_state_findings(), None);
    let jsonl = render_grouped_jsonl(&report, &empty_meta(), false, false, None);
    let lines: Vec<&str> = jsonl.lines().collect();
    // First line meta, then one group line, no informational lines here.
    assert!(serde_json::from_str::<serde_json::Value>(lines[0])
        .unwrap()
        .get("meta")
        .is_some());
    assert_eq!(lines.len(), 2);
    let group: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(group["entry_count"], 3);
}

#[test]
fn plain_and_markdown_mention_the_summary_counts() {
    let report = crate::cmd::scan::grouping::aggregate(three_state_findings(), None);
    let plain = grouped_plain(&report);
    assert!(plain.contains("1 point(s)"));
    assert!(plain.contains("3 parameter"));
    let md = grouped_markdown(&report, &empty_meta(), None);
    assert!(md.contains("Injection points | 1"));
    assert!(md.contains("unverified"));
}
