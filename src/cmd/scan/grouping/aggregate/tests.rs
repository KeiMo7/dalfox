//! Tests for the grouping engine: the acceptance invariants live here —
//! injection-point vs parameter counts, the three verification states,
//! false-positive suppression, deterministic ordering and the memory cap.

use super::*;
use crate::scanning::result::{FindingType, Result, VerifyFailure};

fn finding(tier: FindingType, data: &str, param: &str, location: &str) -> Result {
    let mut r = Result::builder(tier)
        .data(data)
        .param(param)
        .payload("<svg>")
        .build();
    r.location = location.to_string();
    r
}

fn v(data: &str, param: &str, location: &str) -> Result {
    finding(FindingType::Verified, data, param, location)
}
fn r(data: &str, param: &str, location: &str) -> Result {
    finding(FindingType::Reflected, data, param, location)
}

#[test]
fn same_injection_point_different_params_form_one_group_with_many_entries() {
    // Acceptance: one injection surface, three parameters -> one group, three
    // entries, and the param-entry count is exactly the parameter count.
    let findings = vec![
        r("https://a.test/p?a=1", "a", "Query"),
        r("https://a.test/p?b=1", "b", "Query"),
        r("https://a.test/p?c=1", "c", "Query"),
    ];
    let report = aggregate(findings, None);

    assert_eq!(report.injection_point_count(), 1, "one injection surface");
    assert_eq!(report.param_entry_count(), 3, "three parameter entries");
    let group = &report.groups[0];
    let params: Vec<&str> = group.entries.iter().map(|e| e.param.as_str()).collect();
    assert_eq!(params, vec!["a", "b", "c"]);
}

#[test]
fn distinct_surfaces_stay_in_distinct_groups() {
    let findings = vec![
        r("https://a.test/users?q=1", "q", "Query"),
        r("https://a.test/orders?q=1", "q", "Query"),
        r("https://a.test/users?q=1", "q", "Header"),
    ];
    let report = aggregate(findings, None);
    assert_eq!(report.injection_point_count(), 3);
    assert_eq!(report.param_entry_count(), 3);
}

#[test]
fn verification_states_are_separated_and_only_verified_is_high() {
    let mut unverified = r("https://a.test/p?u=1", "u", "Query");
    unverified.verify_failure = Some(VerifyFailure {
        reason: "verification request failed: connection reset".to_string(),
        status: 0,
    });
    let findings = vec![
        v("https://a.test/p?ok=1", "ok", "Query"),
        r("https://a.test/p?maybe=1", "maybe", "Query"),
        unverified,
    ];
    let report = aggregate(findings, None);

    assert_eq!(report.injection_point_count(), 1);
    assert_eq!(report.verified_entry_count(), 1);
    let by_param: HashMap<&str, VerificationStatus> = report.groups[0]
        .entries
        .iter()
        .map(|e| (e.param.as_str(), e.status))
        .collect();
    assert_eq!(by_param["ok"], VerificationStatus::Verified);
    assert_eq!(by_param["maybe"], VerificationStatus::Suspected);
    assert_eq!(by_param["u"], VerificationStatus::Unverified);

    // Only the verified entry counts as high severity.
    let high: Vec<&GroupedEntry> = report.groups[0]
        .entries
        .iter()
        .filter(|e| e.is_high_severity())
        .collect();
    assert_eq!(high.len(), 1);
    assert_eq!(high[0].param, "ok");

    // The failure reason is retained on the unverified entry.
    let u = report.groups[0]
        .entries
        .iter()
        .find(|e| e.param == "u")
        .unwrap();
    assert!(u
        .status_reason
        .as_deref()
        .unwrap_or("")
        .contains("connection reset"));
}

#[test]
fn later_verification_promotes_an_entry() {
    // Same injection point: an R first, then a V on a later payload. The entry
    // must collapse to one and promote to verified.
    let findings = vec![
        r("https://a.test/p?q=1", "q", "Query"),
        v("https://a.test/p?q=2", "q", "Query"),
    ];
    let report = aggregate(findings, None);
    assert_eq!(report.param_entry_count(), 1);
    assert_eq!(report.groups[0].entries[0].status, VerificationStatus::Verified);
    assert_eq!(report.groups[0].entries[0].finding_count, 2);
}

#[test]
fn aggregation_is_deterministic_across_runs() {
    let build = || {
        vec![
            r("https://a.test/p?c=1", "c", "Query"),
            v("https://a.test/p?a=1", "a", "Query"),
            r("https://a.test/p?b=1", "b", "Query"),
        ]
    };
    let first = aggregate(build(), None);
    let second = aggregate(build(), None);
    let order = |report: &GroupedReport| {
        report.groups
            .iter()
            .flat_map(|g| g.entries.iter().map(|e| (e.param.clone(), e.status)))
            .collect::<Vec<_>>()
    };
    assert_eq!(order(&first), order(&second));
    // Within one status, entries sort by parameter name (a before b); the
    // verified entry `a` also happens to lead on status.
    assert_eq!(order(&first)[0].0, "a");
    assert_eq!(
        order(&first).iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        vec!["a", "b", "c"]
    );
}

#[test]
fn informational_findings_are_kept_outside_groups() {
    let info = finding(FindingType::Informational, "https://a.test/", "", "");
    let findings = vec![r("https://a.test/p?q=1", "q", "Query"), info];
    let report = aggregate(findings, None);
    assert_eq!(report.injection_point_count(), 1);
    assert_eq!(report.informational.len(), 1);
    assert_eq!(report.param_entry_count(), 1);
}

#[test]
fn finding_cap_bounds_retained_findings_but_keeps_exact_count() {
    // 20 payload variants on one entry: only ENTRY_FINDING_CAP stored, but the
    // reported count stays 20.
    let findings = (0..20)
        .map(|i| r(&format!("https://a.test/p?q={i}"), "q", "Query"))
        .collect();
    let report = aggregate(findings, None);
    let entry = &report.groups[0].entries[0];
    assert_eq!(entry.finding_count, 20);
    assert_eq!(entry.findings.len(), ENTRY_FINDING_CAP);
}

#[test]
fn empty_input_yields_empty_report() {
    let report = aggregate(Vec::new(), None);
    assert_eq!(report.injection_point_count(), 0);
    assert_eq!(report.reported_finding_count(), 0);
}
