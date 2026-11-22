//! The grouping engine: fold a flat finding list into injection-point groups
//! in one streaming pass.
//!
//! Memory is bounded by the number of *distinct injection points*, not by the
//! number of findings: under `--deep-scan` a reflect-everything endpoint can
//! emit thousands of payload variants for one entry, so each entry retains only
//! the strongest [`ENTRY_FINDING_CAP`] findings verbatim and counts the rest.
//! That keeps a 10k-finding scan's grouping footprint flat while every count,
//! identity and verification state stays exact.
//!
//! The pass is deterministic: groups and entries are emitted in a fixed order
//! (verification strength, then endpoint, location, parameter), so identical
//! inputs produce byte-identical grouping on every run.

use super::identity::{
    VerificationStatus, group_key, group_surface, injection_point_key, status_for_result, stronger,
};
use super::store::GroupingStore;
use crate::scanning::result::{FindingType, Result};
use std::collections::HashMap;

/// How many verbatim findings one entry keeps. The entry still reports the
/// full count; only redundant payload variants stop being retained.
const ENTRY_FINDING_CAP: usize = 5;

/// One parameter-injection entry inside a group. Several raw findings (payload
/// variants, tier escalations) collapse onto one entry keyed by the stable
/// injection-point identity.
#[derive(Debug, Clone)]
pub(crate) struct GroupedEntry {
    pub(crate) entry_key: String,
    pub(crate) param: String,
    pub(crate) status: VerificationStatus,
    /// Populated only when `status == unverified`: the retained transport
    /// reason. Every finding collapsed onto the entry shares the same failed
    /// verification action, so one reason is enough.
    pub(crate) status_reason: Option<String>,
    pub(crate) findings: Vec<Result>,
    pub(crate) finding_count: usize,
    pub(crate) false_positive: bool,
    pub(crate) fp_note: Option<String>,
    pub(crate) fp_repeat_hits: u64,
    pub(crate) first_seen: Option<String>,
    pub(crate) last_confirmed: Option<String>,
    pub(crate) hit_count: u64,
}

impl GroupedEntry {
    /// This entry counts toward the high-severity total only when an actual
    /// verification action asserted exploitability. Suspected and unverified
    /// entries never do, whatever their underlying legacy tier.
    #[allow(dead_code)]
    pub(crate) fn is_high_severity(&self) -> bool {
        self.status == VerificationStatus::Verified
    }
}

/// All parameters sharing one endpoint + wire-location surface.
#[derive(Debug, Clone)]
pub(crate) struct InjectionPointGroup {
    pub(crate) group_id: String,
    pub(crate) endpoint: String,
    pub(crate) location: String,
    pub(crate) entries: Vec<GroupedEntry>,
}

impl InjectionPointGroup {
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn verified_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.status == VerificationStatus::Verified)
            .count()
    }

    pub(crate) fn unverified_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.status == VerificationStatus::Unverified)
            .count()
    }

    pub(crate) fn suspected_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.status == VerificationStatus::Suspected)
            .count()
    }
}

/// The full grouped report plus the bookkeeping the envelope reports.
#[derive(Debug, Clone, Default)]
pub(crate) struct GroupedReport {
    pub(crate) groups: Vec<InjectionPointGroup>,
    /// Informational (`I`, e.g. outdated-library) findings are not XSS
    /// injection points; they are reported separately and never grouped.
    pub(crate) informational: Vec<Result>,
    /// Entries suppressed because a prior run marked them false positives.
    pub(crate) false_positive_suppressed: usize,
    /// Of those, how many actually re-hit this run (always ≤ suppressed).
    pub(crate) false_positive_rehits: usize,
    /// Total raw XSS findings folded into the groups.
    pub(crate) raw_finding_count: usize,
}

impl GroupedReport {
    pub(crate) fn injection_point_count(&self) -> usize {
        self.groups.len()
    }

    pub(crate) fn param_entry_count(&self) -> usize {
        self.groups.iter().map(|g| g.entry_count()).sum()
    }

    pub(crate) fn verified_entry_count(&self) -> usize {
        self.groups.iter().map(|g| g.verified_count()).sum()
    }

    /// The finding total a consumer sees: retained group findings plus the
    /// informational section. Used to keep `findings_count` meaningful.
    pub(crate) fn reported_finding_count(&self) -> usize {
        let grouped: usize = self
            .groups
            .iter()
            .flat_map(|g| g.entries.iter())
            .map(|e| e.findings.len())
            .sum();
        grouped + self.informational.len()
    }
}

/// Where an entry lives inside its group while the pass runs.
struct EntrySlot {
    group_idx: usize,
    entry_idx: usize,
}

/// Fold `findings` into a [`GroupedReport`].
///
/// `store` is optional: without a `--grouping-file`, grouping still works for
/// the current run, but there are no false-positive marks and no cross-run
/// timestamps. When a store is present and active, false-positive entries are
/// suppressed (and their repeat-hit audit row flushed) rather than grouped.
pub(crate) fn aggregate(
    findings: Vec<Result>,
    store: Option<&GroupingStore>,
) -> GroupedReport {
    let mut report = GroupedReport::default();
    // group_id -> index into report.groups
    let mut group_index: HashMap<String, usize> = HashMap::new();
    // entry_key -> its slot
    let mut entry_index: HashMap<String, EntrySlot> = HashMap::new();

    for finding in findings {
        if finding.result_type == FindingType::Informational {
            report.informational.push(finding);
            continue;
        }
        report.raw_finding_count += 1;

        let entry_key = injection_point_key(&finding);

        // False-positive suppression takes precedence over grouping.
        if let Some(store) = store
            && store.is_active()
            && store.is_false_positive(&entry_key)
        {
            report.false_positive_suppressed += 1;
            report.false_positive_rehits += 1;
            // Best-effort audit append; a failed write does not lose the report.
            let _ = store.record_fp_repeat_hit(&entry_key);
            continue;
        }

        let gid = group_key(&finding);
        let (endpoint, location) = group_surface(&finding);

        let group_idx = *group_index.entry(gid.clone()).or_insert_with(|| {
            let idx = report.groups.len();
            report.groups.push(InjectionPointGroup {
                group_id: gid.clone(),
                endpoint,
                location,
                entries: Vec::new(),
            });
            idx
        });

        let slot = entry_index.entry(entry_key.clone()).or_insert_with(|| {
            let entry_idx = report.groups[group_idx].entries.len();
            let history = store.and_then(|s| s.history(&entry_key));
            report.groups[group_idx].entries.push(GroupedEntry {
                entry_key: entry_key.clone(),
                param: finding.param.clone(),
                status: status_for_result(&finding),
                status_reason: finding.verify_failure.as_ref().map(|f| f.reason.clone()),
                findings: Vec::new(),
                finding_count: 0,
                false_positive: false,
                fp_note: store.and_then(|s| s.fp_note(&entry_key)).map(str::to_string),
                fp_repeat_hits: store.map(|s| s.fp_repeat_hits(&entry_key)).unwrap_or(0),
                first_seen: history.map(|h| h.first_seen.clone()),
                last_confirmed: history.map(|h| h.last_confirmed.clone()),
                hit_count: history.map(|h| h.hit_count).unwrap_or(0),
            });
            EntrySlot {
                group_idx,
                entry_idx,
            }
        });

        let entry = &mut report.groups[slot.group_idx].entries[slot.entry_idx];
        entry.finding_count += 1;
        // A later finding can carry a stronger verification state (e.g. an R
        // followed by a V on the same injection point).
        entry.status = stronger(entry.status, status_for_result(&finding));
        if entry.status_reason.is_none() {
            entry.status_reason = finding.verify_failure.as_ref().map(|f| f.reason.clone());
        }
        push_capped(entry, finding);
    }

    sort_report(&mut report);
    report
}

/// Retain at most [`ENTRY_FINDING_CAP`] verbatim findings per entry, always
/// keeping the strongest. New findings arrive in scan order; the cap evicts the
/// weakest present, so the retained set is the top-N by verification/tier.
fn push_capped(entry: &mut GroupedEntry, finding: Result) {
    if entry.findings.len() < ENTRY_FINDING_CAP {
        entry.findings.push(finding);
        return;
    }
    let new_rank = finding_rank(&finding);
    if let Some(weak_pos) = entry
        .findings
        .iter()
        .position(|existing| finding_rank(existing) < new_rank)
    {
        entry.findings[weak_pos] = finding;
    }
    // Otherwise the new finding is no stronger than everything retained: it is
    // counted in `finding_count` but not stored, which is the memory bound.
}

/// Rank used for the retained-finding cap: verification state first, then the
/// legacy tier priority so a V outranks an A outranks an R.
fn finding_rank(r: &Result) -> u8 {
    let state = status_for_result(r).rank();
    let tier = match r.result_type {
        FindingType::Verified => 3,
        FindingType::AstDetected => 2,
        FindingType::Reflected => 1,
        FindingType::Informational => 0,
    };
    state * 4 + tier
}

/// Deterministic ordering, so identical inputs group identically across runs:
/// groups with a verified entry first, then endpoint, location; entries by
/// status strength then parameter name.
fn sort_report(report: &mut GroupedReport) {
    report.groups.sort_by(|a, b| {
        b.verified_count()
            .cmp(&a.verified_count())
            .then_with(|| a.endpoint.cmp(&b.endpoint))
            .then_with(|| a.location.cmp(&b.location))
            .then_with(|| a.group_id.cmp(&b.group_id))
    });
    for group in &mut report.groups {
        group.entries.sort_by(|a, b| {
            // Semantic strength, not the enum discriminant: the declaration
            // order (verified/unverified/suspected) is not the rank order.
            b.status
                .rank()
                .cmp(&a.status.rank())
                .then_with(|| a.param.cmp(&b.param))
                .then_with(|| a.entry_key.cmp(&b.entry_key))
        });
    }
}

#[cfg(test)]
mod tests;
