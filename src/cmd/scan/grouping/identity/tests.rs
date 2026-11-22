//! Tests for the stable identity vocabulary. These pin the hard constraints:
//! identity must not depend on payload/time, identical inputs must hash
//! identically across runs, and different parameters of the same surface must
//! share a group while keeping distinct entry keys.

use super::*;
use crate::scanning::result::{FindingType, Result};

fn reflected(data: &str, param: &str, location: &str, payload: &str) -> Result {
    let mut r = Result::builder(FindingType::Reflected)
        .data(data)
        .param(param)
        .payload(payload)
        .build();
    r.location = location.to_string();
    r
}

#[test]
fn payload_changes_do_not_change_identity() {
    let r1 = reflected(
        "https://shop.example/search?q=%3Csvg%3E&x=1",
        "q",
        "Query",
        "<svg>",
    );
    let r2 = reflected(
        "https://shop.example/search?q=%3Cimg%3E&x=2",
        "q",
        "Query",
        "<img>",
    );
    assert_eq!(injection_point_key(&r1), injection_point_key(&r2));
    assert_eq!(group_key(&r1), group_key(&r2));
}

#[test]
fn same_input_hashes_identically_on_every_run() {
    // The key is a pure function of the finding; there is no clock or random
    // input, so building it twice must give byte-identical output.
    let r = reflected("https://a.test/p?a=1", "a", "Query", "x");
    assert_eq!(injection_point_key(&r), injection_point_key(&r.clone()));
    assert_eq!(group_key(&r), group_key(&r.clone()));
}

#[test]
fn different_params_share_a_group_but_keep_distinct_entries() {
    let a = reflected("https://a.test/p?a=1", "a", "Query", "x");
    let b = reflected("https://a.test/p?b=1", "b", "Query", "x");
    assert_eq!(group_key(&a), group_key(&b));
    assert_ne!(injection_point_key(&a), injection_point_key(&b));
}

#[test]
fn location_is_part_of_identity() {
    let query = reflected("https://a.test/p?q=1", "q", "Query", "x");
    let header = reflected("https://a.test/p", "q", "Header", "x");
    assert_ne!(group_key(&query), group_key(&header));
    assert_ne!(injection_point_key(&query), injection_point_key(&header));
}

#[test]
fn endpoint_path_is_part_of_group_identity() {
    let one = reflected("https://a.test/users?q=1", "q", "Query", "x");
    let two = reflected("https://a.test/orders?q=1", "q", "Query", "x");
    assert_ne!(group_key(&one), group_key(&two));
}

#[test]
fn host_case_and_default_port_are_normalized() {
    let lower = reflected("https://a.test/p?q=1", "q", "Query", "x");
    let upper = reflected("https://A.TEST:443/p?q=2", "q", "Query", "x");
    assert_eq!(group_key(&lower), group_key(&upper));
    assert_eq!(injection_point_key(&lower), injection_point_key(&upper));
}

#[test]
fn non_default_port_splits_endpoints() {
    let plain = reflected("https://a.test/p?q=1", "q", "Query", "x");
    let alt = reflected("https://a.test:8443/p?q=1", "q", "Query", "x");
    assert_ne!(group_key(&plain), group_key(&alt));
}

#[test]
fn path_injection_wildcards_the_payload_segment() {
    let first = reflected("https://a.test/files/abc123", "path", "Path", "abc123");
    let second = reflected("https://a.test/files/zzz999", "path", "Path", "zzz999");
    assert_eq!(group_key(&first), group_key(&second));
    assert_eq!(
        normalized_endpoint(first.data.as_str(), "Path", "abc123"),
        "https://a.test/files/*"
    );
}

#[test]
fn query_path_segments_are_not_wildcarded_without_payload() {
    let r = reflected("https://a.test/users/42?q=1", "q", "Query", "<svg>");
    assert_eq!(
        normalized_endpoint(r.data.as_str(), "Query", "<svg>"),
        "https://a.test/users/42"
    );
}

#[test]
fn unparseable_url_does_not_panic_and_stays_distinct() {
    let r = reflected("not a url at all", "q", "Query", "x");
    // Must still produce a stable, non-empty key.
    assert!(!injection_point_key(&r).is_empty());
    assert_eq!(injection_point_key(&r), injection_point_key(&r.clone()));
}

#[test]
fn failed_verification_is_never_verified() {
    use crate::scanning::result::VerifyFailure;
    let mut r = Result::builder(FindingType::Reflected)
        .data("https://a.test/p?q=1")
        .param("q")
        .payload("x")
        .build();
    r.location = "Query".to_string();
    assert_eq!(status_for_result(&r), VerificationStatus::Suspected);

    r.verify_failure = Some(VerifyFailure {
        reason: "verification request failed: connection reset".to_string(),
        status: 0,
    });
    assert_eq!(status_for_result(&r), VerificationStatus::Unverified);

    // Even if something later flips the tier, the recorded failure wins.
    r.result_type = FindingType::Verified;
    assert_eq!(status_for_result(&r), VerificationStatus::Unverified);
}

#[test]
fn verified_tier_maps_to_verified_state() {
    let r = Result::builder(FindingType::Verified)
        .data("https://a.test/p?q=1")
        .param("q")
        .build();
    assert_eq!(status_for_result(&r), VerificationStatus::Verified);
}

#[test]
fn stronger_state_orders_correctly() {
    use VerificationStatus::*;
    assert_eq!(stronger(Verified, Suspected), Verified);
    assert_eq!(stronger(Suspected, Unverified), Unverified);
    assert_eq!(stronger(Unverified, Verified), Verified);
    assert_eq!(stronger(Suspected, Suspected), Suspected);
}
