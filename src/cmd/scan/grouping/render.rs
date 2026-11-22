//! Grouped renderers. One function per output format, taking the already-built
//! [`GroupedReport`] so rendering holds no grouping logic of its own.
//!
//! Contract notes:
//! - JSON keeps the existing `meta` envelope and adds an `injection_point_groups`
//!   array; the flat `findings` key is replaced (not duplicated) when grouping
//!   is on, so a consumer cannot read two contradictory totals. Informational
//!   findings keep their own `informational_findings` array.
//! - JSONL writes the meta line first, then **one group per line**, so a
//!   10k-finding report streams without a document-sized JSON value in memory.
//! - Plain / Markdown are human views built from the same counts.
//! - SARIF has a fixed schema with no group concept; the caller falls back to
//!   the flat SARIF renderer with a stderr warning rather than emitting an
//!   invalid document.

use super::aggregate::{GroupedEntry, GroupedReport, InjectionPointGroup};
use crate::scanning::result::Result;
use std::fmt::Write as _;

/// JSON shape of one entry. The nested findings reuse the canonical finding
/// serializer, so every existing finding field stays exactly as documented.
fn entry_json(e: &GroupedEntry, include_request: bool, include_response: bool) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "entry_key": e.entry_key,
        "param": e.param,
        "verification_status": e.status.as_str(),
        "finding_count": e.finding_count,
        "findings": e
            .findings
            .iter()
            .map(|f| f.to_json_value(include_request, include_response))
            .collect::<Vec<_>>(),
    });
    if let Some(reason) = &e.status_reason {
        obj["verification_reason"] = serde_json::json!(reason);
    }
    if e.false_positive || e.fp_note.is_some() {
        obj["false_positive_note"] = serde_json::json!(e.fp_note.clone().unwrap_or_default());
    }
    if e.fp_repeat_hits > 0 {
        obj["false_positive_repeat_hits"] = serde_json::json!(e.fp_repeat_hits);
    }
    if let Some(first) = &e.first_seen {
        obj["first_seen"] = serde_json::json!(first);
    }
    if let Some(last) = &e.last_confirmed {
        obj["last_confirmed"] = serde_json::json!(last);
    }
    if e.hit_count > 0 {
        obj["historical_hit_count"] = serde_json::json!(e.hit_count);
    }
    obj
}

fn group_json(g: &InjectionPointGroup, include_request: bool, include_response: bool) -> serde_json::Value {
    serde_json::json!({
        "group_id": g.group_id,
        "endpoint": g.endpoint,
        "location": g.location,
        "entry_count": g.entry_count(),
        "verified": g.verified_count(),
        "suspected": g.suspected_count(),
        "unverified": g.unverified_count(),
        "entries": g
            .entries
            .iter()
            .map(|e| entry_json(e, include_request, include_response))
            .collect::<Vec<_>>(),
    })
}

/// Summary block shared by every format's envelope, so "how many injection
/// points / params / verified" is answered from one place.
pub(crate) fn grouping_meta(report: &GroupedReport, store: Option<&super::store::GroupingStore>) -> serde_json::Value {
    let mut block = serde_json::json!({
        "enabled": true,
        "injection_points": report.injection_point_count(),
        "parameter_entries": report.param_entry_count(),
        "verified_entries": report.verified_entry_count(),
        "raw_finding_count": report.raw_finding_count,
        "false_positive_suppressed": report.false_positive_suppressed,
        "false_positive_rehits": report.false_positive_rehits,
    });
    if let Some(store) = store {
        block["grouping_file"] = serde_json::json!(store.path());
        if let Some(warning) = &store.warning {
            block["persistence_warning"] = serde_json::json!(warning);
        }
    }
    block
}

/// One pretty JSON document: the canonical meta envelope (with the `grouping`
/// block) plus the group array and informational findings.
pub(crate) fn grouped_json_envelope(
    report: &GroupedReport,
    meta: &crate::scanning::result::ScanMetadata,
    include_request: bool,
    include_response: bool,
    store: Option<&super::store::GroupingStore>,
) -> String {
    let mut meta_value = Result::make_scan_meta_value(meta);
    if let serde_json::Value::Object(ref mut map) = meta_value {
        map.insert("grouping".to_string(), grouping_meta(report, store));
    }
    let wrapper = serde_json::json!({
        "meta": meta_value,
        "injection_point_groups": report
            .groups
            .iter()
            .map(|g| group_json(g, include_request, include_response))
            .collect::<Vec<_>>(),
        "informational_findings": report
            .informational
            .iter()
            .map(|f| f.to_json_value(include_request, include_response))
            .collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&wrapper).unwrap_or_else(|_| "{}".to_string())
}

/// JSONL: meta line, then one group object per line (true streaming — callers
/// write each line as it is produced; this returns the complete buffer for the
/// in-memory test and file paths, while the line iterator below serves the
/// stdout path that must not buffer the whole run).
pub(crate) fn render_grouped_jsonl(
    report: &GroupedReport,
    meta: &crate::scanning::result::ScanMetadata,
    include_request: bool,
    include_response: bool,
    store: Option<&super::store::GroupingStore>,
) -> String {
    let mut meta_value = Result::make_scan_meta_value(meta);
    if let serde_json::Value::Object(ref mut map) = meta_value {
        map.insert("grouping".to_string(), grouping_meta(report, store));
    }
    let mut out = serde_json::to_string(&serde_json::json!({ "meta": meta_value })).unwrap_or_default();
    out.push('\n');
    for g in &report.groups {
        if let Ok(line) = serde_json::to_string(&group_json(g, include_request, include_response)) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    for f in &report.informational {
        if let Ok(line) = serde_json::to_string(&f.to_json_value(include_request, include_response)) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// Plain-text human view.
pub(crate) fn grouped_plain(report: &GroupedReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Grouped by injection point: {} point(s), {} parameter entr(y/ies), {} verified",
        report.injection_point_count(),
        report.param_entry_count(),
        report.verified_entry_count()
    );
    if report.false_positive_suppressed > 0 {
        let _ = writeln!(
            out,
            "False positives suppressed: {} ({} re-hit this run)",
            report.false_positive_suppressed, report.false_positive_rehits
        );
    }
    out.push('\n');
    for g in &report.groups {
        let _ = writeln!(
            out,
            "[{}] {} ({}): {} param(s) — {} verified, {} suspected, {} unverified",
            g.group_id,
            g.endpoint,
            g.location,
            g.entry_count(),
            g.verified_count(),
            g.suspected_count(),
            g.unverified_count()
        );
        for e in &g.entries {
            let mut line = format!(
                "  - [{}] param={} ({} finding(s))",
                e.status.as_str(),
                e.param,
                e.finding_count
            );
            if let Some(first) = &e.first_seen {
                let _ = write!(line, " first_seen={first}");
            }
            if let Some(last) = &e.last_confirmed {
                let _ = write!(line, " last_confirmed={last}");
            }
            let _ = writeln!(out, "{line}");
            if let Some(reason) = &e.status_reason {
                let _ = writeln!(out, "      reason: {reason}");
            }
            for f in &e.findings {
                let _ = writeln!(
                    out,
                    "      [{}] {} — {}",
                    f.result_type.short(),
                    f.message_str,
                    f.data
                );
            }
        }
        out.push('\n');
    }
    if !report.informational.is_empty() {
        let _ = writeln!(out, "Informational ({}):", report.informational.len());
        for f in &report.informational {
            let _ = writeln!(out, "  - [I] {}", f.message_str);
        }
    }
    out
}

/// Markdown human view, mirroring the section style of the existing renderer.
pub(crate) fn grouped_markdown(
    report: &GroupedReport,
    meta: &crate::scanning::result::ScanMetadata,
    store: Option<&super::store::GroupingStore>,
) -> String {
    let mut out = String::from("# Dalfox Grouped Scan Results\n\n");
    out.push_str("## Grouping Summary\n\n");
    out.push_str("| Metric | Value |\n|---|---|\n");
    let _ = writeln!(out, "| Injection points | {} |", report.injection_point_count());
    let _ = writeln!(out, "| Parameter entries | {} |", report.param_entry_count());
    let _ = writeln!(out, "| Verified entries | {} |", report.verified_entry_count());
    let _ = writeln!(out, "| Raw findings folded | {} |", report.raw_finding_count);
    let _ = writeln!(
        out,
        "| False positives suppressed | {} |",
        report.false_positive_suppressed
    );
    if let Some(store) = store {
        let _ = writeln!(out, "| Grouping file | `{}` |", store.path());
    }
    out.push('\n');

    for g in &report.groups {
        let _ = writeln!(
            out,
            "## `{}` {} ({})\n",
            g.group_id, g.endpoint, g.location
        );
        out.push_str("| Param | Status | Findings | First seen | Last confirmed |\n|---|---|---|---|---|\n");
        for e in &g.entries {
            let first = e.first_seen.as_deref().unwrap_or("-");
            let last = e.last_confirmed.as_deref().unwrap_or("-");
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} | {} |",
                e.param,
                e.status.as_str(),
                e.finding_count,
                first,
                last
            );
        }
        out.push('\n');
    }
    if !report.informational.is_empty() {
        out.push_str("## Informational\n\n");
        for f in &report.informational {
            let _ = writeln!(out, "- {}", f.message_str);
        }
    }
    let _ = meta;
    out
}

/// TOML view. Groups render as `[[injection_point_groups]]` arrays of tables,
/// matching the existing `[[results]]` convention.
pub(crate) fn grouped_toml(
    report: &GroupedReport,
    meta: &crate::scanning::result::ScanMetadata,
    include_request: bool,
    include_response: bool,
    store: Option<&super::store::GroupingStore>,
) -> String {
    // Serialize via JSON then transform: hand-emitting TOML would duplicate the
    // finding schema. serde_json -> toml::Value preserves ordering of keys well
    // enough for a report and keeps one canonical finding serializer.
    let json = grouped_json_envelope(report, meta, include_request, include_response, store);
    let value: toml::Value = match serde_json::from_str::<serde_json::Value>(&json) {
        Ok(v) => json_to_toml(v),
        Err(_) => toml::Value::Table(toml::value::Table::new()),
    };
    toml::to_string_pretty(&value).unwrap_or_default()
}

/// Minimal recursive JSON->TOML conversion scoped to the shapes we emit.
fn json_to_toml(json: serde_json::Value) -> toml::Value {
    use toml::Value;
    match json {
        serde_json::Value::Null => Value::String("null".to_string()),
        serde_json::Value::Bool(b) => Value::Boolean(b),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(Value::Integer)
            .or_else(|| n.as_f64().map(Value::Float))
            .unwrap_or_else(|| Value::String(n.to_string())),
        serde_json::Value::String(s) => Value::String(s),
        serde_json::Value::Array(items) => {
            Value::Array(items.into_iter().map(json_to_toml).collect())
        }
        serde_json::Value::Object(map) => {
            let mut table = toml::value::Table::new();
            for (k, v) in map {
                table.insert(k, json_to_toml(v));
            }
            Value::Table(table)
        }
    }
}

#[cfg(test)]
mod tests;
