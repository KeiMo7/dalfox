//! Stable injection-point identity and the verification-status vocabulary
//! shared by every other file in the `grouping` module.
//!
//! Two identity levels exist, and the distinction is the whole feature:
//!
//! - [`injection_point_key`] identifies **one parameter at one wire location on
//!   one normalized endpoint**. It is built only from the normalized URL, the
//!   parameter name and its injection location — never from a scan time, a
//!   payload, a tier or an evidence string, so byte-identical inputs produce the
//!   same key on every run (hard constraint: stable identity).
//! - [`group_key`] drops the parameter name: it identifies the *endpoint +
//!   location surface*, so hits on different parameters of the same injection
//!   surface (e.g. `?a=…&b=…` both reflected into the same HTML context) fold
//!   into one group whose entries list every parameter.

use crate::scanning::result::Result;
use sha2::{Digest, Sha256};

/// The three verification states a grouped entry can carry.
///
/// The state always comes from a recorded verification **action**, never from a
/// rule guessed at render time:
///
/// - [`VerificationStatus::Verified`] — an actual verification action asserted
///   exploitability (DOM verification, a static V upgrade that parsed executable
///   DOM structure, or an out-of-band callback — the only path that observes
///   execution). Only verified entries count as high severity.
/// - [`VerificationStatus::Unverified`] — a verification request was attempted
///   and failed (transport error / timeout / unreadable body). The failure
///   reason is retained. A failed verification can never become `Verified`.
/// - [`VerificationStatus::Suspected`] — a signal without a completed
///   verification action: a raw reflection (`R`), an AST source→sink finding
///   (`A`), or a DOM phase that answered but never proved an executable
///   position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerificationStatus {
    /// A verification action asserted the input is exploitable.
    Verified,
    /// A verification request was attempted but failed; reason retained.
    Unverified,
    /// A signal was observed but no verification action completed.
    Suspected,
}

impl VerificationStatus {
    /// Stable lowercase wire label used in JSON reports and the grouping file.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            VerificationStatus::Verified => "verified",
            VerificationStatus::Unverified => "unverified",
            VerificationStatus::Suspected => "suspected",
        }
    }

    /// Human label for the plain / Markdown renderers.
    #[allow(dead_code)]
    pub(crate) fn label(self) -> &'static str {
        match self {
            VerificationStatus::Verified => "已验证",
            VerificationStatus::Unverified => "未验证",
            VerificationStatus::Suspected => "疑似",
        }
    }

    /// Ordering for "strongest state wins" when several hits map to one entry.
    pub(crate) fn rank(self) -> u8 {
        match self {
            VerificationStatus::Verified => 3,
            VerificationStatus::Unverified => 2,
            VerificationStatus::Suspected => 1,
        }
    }
}

/// Payload- and time-invariant normalization of a finding's target URL.
///
/// Scheme and host are lower-cased, the default port for the scheme is dropped,
/// the query and fragment are removed, and a payload-carrying path segment is
/// replaced by `*`. Mirrors the conservatism of the baseline identity helper:
/// anything we cannot prove carries the payload keeps its full path, erring
/// toward *more* groups (noise) rather than merging two distinct endpoints (a
/// missed distinction).
///
/// The input is the finding's own `data` URL (the as-sent PoC URL), so this
/// works for deserialized reports as well as live findings.
pub(crate) fn normalized_endpoint(data: &str, location: &str, payload: &str) -> String {
    let raw = data.split('#').next().unwrap_or(data);
    let path_and_query = raw.split('?').next().unwrap_or(raw);

    let Ok(parsed) = url::Url::parse(raw) else {
        // Unparseable finding URL: keep the payload-free string verbatim rather
        // than hashing every odd record into the same bucket.
        return wildcard_last_segment(path_and_query, location, payload);
    };

    let scheme = parsed.scheme().to_ascii_lowercase();
    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    let port = parsed.port();
    let default_port = matches!((scheme.as_str(), port), ("https", Some(443)) | ("http", Some(80)));
    let authority = match port {
        Some(p) if !default_port => format!("{host}:{p}"),
        _ => host,
    };

    let wildcarded = wildcard_last_segment(parsed.path(), location, payload);
    format!("{scheme}://{authority}{wildcarded}")
}

/// Replace the last path segment with `*` when the payload lives there.
///
/// `Location::Path` always replaces it (path injection substitutes the
/// segment by construction); otherwise the segment is only replaced when its
/// raw or percent-decoded text contains the payload, which is how DOM-XSS POC
/// URLs render a `location.pathname` source.
fn wildcard_last_segment(path: &str, location: &str, payload: &str) -> String {
    let Some(slash) = path.rfind('/') else {
        return path.to_string();
    };
    let (parent, last) = path.split_at(slash + 1);
    if last.is_empty() {
        return path.to_string();
    }
    let carries = location == "Path"
        || (!payload.is_empty()
            && (last.contains(payload)
                || urlencoding::decode(last)
                    .map(|d| d.contains(payload))
                    .unwrap_or(false)));
    if carries {
        format!("{parent}*")
    } else {
        path.to_string()
    }
}

/// Digest the identity parts into a compact, filesystem- and JSON-safe key.
/// A versioned prefix (`k1|`) keeps a future identity-scheme change from
/// silently colliding with keys written under this one.
fn digest(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"k1");
    for part in parts {
        hasher.update([0u8]);
        hasher.update(part.as_bytes());
    }
    let hex_full = hex::encode(hasher.finalize());
    hex_full[..16].to_string()
}

/// Stable identity of one parameter-injection instance:
/// normalized endpoint + wire location + parameter name.
///
/// Deliberately excludes payload, tier, evidence, timestamps and the query
/// string (its payload varies every run). Two findings that differ only by
/// those fields — including the same finding re-surfaced in a later scan —
/// produce the same key.
pub(crate) fn injection_point_key(r: &Result) -> String {
    let endpoint = normalized_endpoint(&r.data, &r.location, &r.payload);
    digest(&[&endpoint, &r.location, &r.param])
}

/// Identity of the group the entry belongs to: normalized endpoint + wire
/// location, without the parameter name.
pub(crate) fn group_key(r: &Result) -> String {
    let endpoint = normalized_endpoint(&r.data, &r.location, &r.payload);
    digest(&[&endpoint, &r.location])
}

/// The endpoint + location a group's human-readable header shows. Kept beside
/// the digest keys so the report can say *what* a group is without the reader
/// having to reverse a hash.
pub(crate) fn group_surface(r: &Result) -> (String, String) {
    let endpoint = normalized_endpoint(&r.data, &r.location, &r.payload);
    (endpoint, r.location.clone())
}

/// Derive a single finding's verification state from the verification actions
/// recorded on it. Pure, and shared by the live path and the tests.
///
/// Rules:
/// 1. A recorded verification failure ([`Result::verify_failure`]) makes the
///    entry [`VerificationStatus::Unverified`] — a failed request can never be
///    read as verified, regardless of tier.
/// 2. A `V` (or OOB `V`) is [`VerificationStatus::Verified`]: the tier is only
///    ever minted by an action that parsed executable DOM structure or observed
///    an out-of-band callback.
/// 3. Everything else (`R`, `A`, …) is [`VerificationStatus::Suspected`].
pub(crate) fn status_for_result(r: &Result) -> VerificationStatus {
    if r.verify_failure.is_some() {
        return VerificationStatus::Unverified;
    }
    if r.result_type == crate::scanning::result::FindingType::Verified {
        return VerificationStatus::Verified;
    }
    VerificationStatus::Suspected
}

/// Strongest of two states, used when several hits collapse onto one entry.
/// `Verified` outranks `Unverified` outranks `Suspected`: a later successful
/// verification promotes an entry that earlier failed, while a single failure
/// still lifts a bare suspicion to "we tried and could not confirm".
pub(crate) fn stronger(a: VerificationStatus, b: VerificationStatus) -> VerificationStatus {
    if a.rank() >= b.rank() { a } else { b }
}

#[cfg(test)]
mod tests;
