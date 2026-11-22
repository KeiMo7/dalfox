//! The grouping file: append-only JSONL persistence behind
//! `--grouping-file`.
//!
//! Two kinds of memory live here, both keyed by the stable injection-point
//! identity from [`super::identity`]:
//!
//! - **False-positive marks.** An operator marks an entry with
//!   `dalfox findings mark-fp <file> <id>`. On later scans the entry is
//!   suppressed from the report, but its record is never deleted: every later
//!   hit appends a `repeat_hit` and bumps `fp_repeat_hits`, so the suppression
//!   and its re-occurrences stay auditable.
//! - **Cross-run history.** Every entry observed in a grouped report is upserted
//!   (last line wins) with `first_seen` preserved and `last_confirmed` refreshed,
//!   so the same finding re-appearing in a later scan is recognized and shown
//!   with both timestamps and its hit count.
//!
//! Line shapes (one JSON object per line):
//!
//! ```text
//! {"dalfox_grouping":1,"version":"3.x.0","created":"<rfc3339>"}
//! {"kind":"history","entry_key":"<id>","group_key":"<id>","endpoint":"https://…",
//!  "location":"Query","param":"q","first_seen":"…","last_confirmed":"…","hit_count":3}
//! {"kind":"false_positive","entry_key":"<id>","marked_at":"…","note":"…",
//!  "fp_repeat_hits":1,"last_repeat_hit":"…"}
//! ```
//!
//! Append-only by design, following the state-file module: a hard kill can at
//! worst tear the final line, which [`GroupingStore::load`] skips; nothing is
//! rewritten in place, so there is no window where the file is invalid. Read
//! failures are soft — a malformed or foreign file disables persistence with a
//! warning rather than failing the scan.

use super::identity::injection_point_key;
use crate::scanning::result::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Bumped only on an incompatible record-schema change. A file claiming a
/// newer version is ignored (persistence disabled), never misread.
pub(crate) const GROUPING_FORMAT_VERSION: u32 = 1;

/// Upper bound on a grouping file we will read back. Records are a few hundred
/// bytes, so 256 MiB holds around a million entries while failing fast on a
/// path that resolves to something unbounded. Same ceiling as the state file.
pub(crate) const MAX_GROUPING_FILE_BYTES: u64 = 256 << 20;

/// The in-memory tables `load` produces: history rows, false-positive marks,
/// and the count of unparseable lines skipped.
type LoadedTables = (
    HashMap<String, HistoryRecord>,
    HashMap<String, FalsePositiveRecord>,
    usize,
);

#[derive(Serialize, Deserialize)]
struct Header {
    dalfox_grouping: u32,
    version: String,
    created: String,
}

/// One persisted history row for an injection-point entry. It has no `kind`
/// field of its own: the [`Row`] enum's internal tag supplies
/// `"kind":"history"` on both serialize and deserialize.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct HistoryRecord {
    pub(crate) entry_key: String,
    #[serde(default)]
    pub(crate) group_key: String,
    #[serde(default)]
    pub(crate) endpoint: String,
    #[serde(default)]
    pub(crate) location: String,
    #[serde(default)]
    pub(crate) param: String,
    pub(crate) first_seen: String,
    pub(crate) last_confirmed: String,
    #[serde(default)]
    pub(crate) hit_count: u64,
}

/// One persisted false-positive row.
///
/// `removed` is the append-only tombstone used by `unmark-fp`: the row stays in
/// the file (the audit trail is preserved) but [`GroupingStore::load`] drops it,
/// so the entry is reported again on later scans. Like [`HistoryRecord`], the
/// `"kind":"false_positive"` discriminator comes from the [`Row`] tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct FalsePositiveRecord {
    pub(crate) entry_key: String,
    pub(crate) marked_at: String,
    #[serde(default)]
    pub(crate) note: String,
    #[serde(default)]
    pub(crate) fp_repeat_hits: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_repeat_hit: Option<String>,
    /// Tombstone marker. Absent on ordinary marks (defaults to `false`).
    #[serde(default)]
    pub(crate) removed: bool,
}

/// Either on-disk row, discriminated by the flat `kind` field. Internal tagging
/// injects the tag into the flattened struct, so the row structs themselves must
/// not also declare a `kind` field.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Row {
    History(HistoryRecord),
    FalsePositive(FalsePositiveRecord),
}

/// The loaded memory for one scan, plus the open append handle when this
/// process is allowed to write.
pub(crate) struct GroupingStore {
    path: String,
    history: HashMap<String, HistoryRecord>,
    false_positives: HashMap<String, FalsePositiveRecord>,
    /// Entry keys whose history row this run already appended, so a finding
    /// observed through several in-memory paths is written at most once.
    history_dirty: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Entry keys whose repeat-hit counter this run already flushed.
    fp_dirty: std::sync::Mutex<std::collections::HashSet<String>>,
    handle: Option<std::fs::File>,
    /// Why persistence is disabled, if it is. The grouping report still works;
    /// only cross-run memory and FP suppression are off.
    pub(crate) warning: Option<String>,
    /// Unparseable lines skipped while reading (a torn final line, normally).
    pub(crate) corrupt_lines: usize,
}

impl GroupingStore {
    /// Load `path` for a scanning run and open it for appending. A missing file
    /// is the ordinary first run: a fresh store, and the first write creates it
    /// (`0600` on Unix — the file can name internal endpoints and params).
    pub(crate) fn open(path: &str) -> Self {
        match Self::load(path) {
            Ok((history, false_positives, corrupt_lines)) => {
                let opened = open_append(path);
                let (handle, warning) = match opened {
                    Ok(mut f) => {
                        // A brand-new (empty) file needs its header now, so the
                        // first appended row is not mistaken for a header and a
                        // later run recognizes the file. An existing file keeps
                        // whatever header `load` already validated.
                        let needs_header = f
                            .metadata()
                            .map(|m| m.len() == 0)
                            .unwrap_or(true);
                        let header_warn = if needs_header {
                            write_header(&mut f).err().map(|e| {
                                format!("grouping file '{}' header write failed: {}", path, e)
                            })
                        } else {
                            None
                        };
                        (Some(f), header_warn)
                    }
                    Err(e) => (
                        None,
                        Some(format!("grouping file '{}' is not writable: {}", path, e)),
                    ),
                };
                GroupingStore {
                    path: path.to_string(),
                    history,
                    false_positives,
                    history_dirty: Default::default(),
                    fp_dirty: Default::default(),
                    handle,
                    warning,
                    corrupt_lines,
                }
            }
            Err(warning) => GroupingStore {
                path: path.to_string(),
                history: HashMap::new(),
                false_positives: HashMap::new(),
                history_dirty: Default::default(),
                fp_dirty: Default::default(),
                handle: None,
                warning: Some(warning),
                corrupt_lines: 0,
            },
        }
    }

    /// Read-only load used by the one-shot `findings` subcommands. They mutate
    /// the file through their own append helper rather than holding this handle.
    pub(crate) fn load_only(path: &str) -> std::result::Result<Self, String> {
        let (history, false_positives, corrupt_lines) = Self::load(path)?;
        Ok(GroupingStore {
            path: path.to_string(),
            history,
            false_positives,
            history_dirty: Default::default(),
            fp_dirty: Default::default(),
            handle: None,
            warning: None,
            corrupt_lines,
        })
    }

    fn load(path: &str) -> std::result::Result<LoadedTables, String> {
        let raw = match std::fs::metadata(path) {
            Err(_) => return Ok((HashMap::new(), HashMap::new(), 0)),
            Ok(_) => crate::utils::fs::read_bounded(
                Path::new(path),
                MAX_GROUPING_FILE_BYTES,
                "grouping file",
            )
            .map_err(|e| format!("grouping file '{}' could not be read: {}", path, e))?,
        };
        if raw.trim().is_empty() {
            return Ok((HashMap::new(), HashMap::new(), 0));
        }

        let mut lines = raw.lines().filter(|l| !l.trim().is_empty());
        let header: Header = match lines.next().map(serde_json::from_str::<Header>) {
            Some(Ok(h)) => h,
            _ => {
                return Err(format!(
                    "grouping file '{}' is not a dalfox grouping file (no grouping header on its first line)",
                    path
                ));
            }
        };
        if header.dalfox_grouping != GROUPING_FORMAT_VERSION {
            return Err(format!(
                "grouping file '{}' uses grouping format v{} but this build writes v{}",
                path, header.dalfox_grouping, GROUPING_FORMAT_VERSION
            ));
        }

        let mut history = HashMap::new();
        let mut false_positives = HashMap::new();
        let mut corrupt_lines = 0usize;
        for line in lines {
            match serde_json::from_str::<Row>(line) {
                Ok(Row::History(rec)) => {
                    // Last line wins: an upsert history always appends a fresh
                    // full row, so the final occurrence is the current truth.
                    history.insert(rec.entry_key.clone(), rec);
                }
                Ok(Row::FalsePositive(rec)) => {
                    // A later tombstone removes the mark while keeping the row
                    // in the file as an audit trail.
                    if rec.removed {
                        false_positives.remove(&rec.entry_key);
                    } else {
                        false_positives.insert(rec.entry_key.clone(), rec);
                    }
                }
                Err(_) => corrupt_lines += 1,
            }
        }
        Ok((history, false_positives, corrupt_lines))
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn is_active(&self) -> bool {
        self.warning.is_none()
    }

    pub(crate) fn is_false_positive(&self, entry_key: &str) -> bool {
        self.false_positives.contains_key(entry_key)
    }

    pub(crate) fn fp_note(&self, entry_key: &str) -> Option<&str> {
        self.false_positives
            .get(entry_key)
            .map(|r| r.note.as_str())
    }

    pub(crate) fn fp_repeat_hits(&self, entry_key: &str) -> u64 {
        self.false_positives
            .get(entry_key)
            .map(|r| r.fp_repeat_hits)
            .unwrap_or(0)
    }

    pub(crate) fn history(&self, entry_key: &str) -> Option<&HistoryRecord> {
        self.history.get(entry_key)
    }

    /// The full false-positive record for `entry_key`, for the one-shot
    /// `unmark-fp` subcommand (which must append a tombstone preserving the
    /// original mark's fields).
    pub(crate) fn false_positive_record(
        &self,
        entry_key: &str,
    ) -> Option<&FalsePositiveRecord> {
        self.false_positives.get(entry_key)
    }

    /// Record one observed entry after a report is written. Preserves
    /// `first_seen` across runs, refreshes `last_confirmed`, and accumulates
    /// `hit_count`. Appends at most one row per entry per run. Returns false
    /// when the write could not happen (the caller warns once; the report
    /// itself is already safely on disk).
    pub(crate) fn record_observation(
        &self,
        result: &Result,
        group_id: &str,
        endpoint: &str,
    ) -> bool {
        let entry_key = injection_point_key(result);
        let now = chrono::Local::now().to_rfc3339();
        if !self.history_dirty.lock().unwrap().insert(entry_key.clone()) {
            return true;
        }
        let record = match self.history.get(&entry_key) {
            Some(prev) => HistoryRecord {
                entry_key: entry_key.clone(),
                group_key: group_id.to_string(),
                endpoint: endpoint.to_string(),
                location: result.location.clone(),
                param: result.param.clone(),
                first_seen: prev.first_seen.clone(),
                last_confirmed: now,
                hit_count: prev.hit_count.saturating_add(1),
            },
            None => HistoryRecord {
                entry_key: entry_key.clone(),
                group_key: group_id.to_string(),
                endpoint: endpoint.to_string(),
                location: result.location.clone(),
                param: result.param.clone(),
                first_seen: now.clone(),
                last_confirmed: now,
                hit_count: 1,
            },
        };
        self.append_line(
            serde_json::to_string(&Row::History(record)).unwrap_or_default(),
        )
    }

    /// A suppressed false-positive hit re-occurred this run: bump the audit
    /// counter once per entry per run and stamp the time.
    pub(crate) fn record_fp_repeat_hit(&self, entry_key: &str) -> bool {
        if !self.fp_dirty.lock().unwrap().insert(entry_key.to_string()) {
            return true;
        }
        let Some(rec) = self.false_positives.get(entry_key) else {
            return true;
        };
        let now = chrono::Local::now().to_rfc3339();
        let updated = FalsePositiveRecord {
            fp_repeat_hits: rec.fp_repeat_hits.saturating_add(1),
            last_repeat_hit: Some(now.clone()),
            ..rec.clone()
        };
        self.append_line(
            serde_json::to_string(&Row::FalsePositive(updated)).unwrap_or_default(),
        )
    }

    fn append_line(&self, line: String) -> bool {
        let Some(handle) = self.handle.as_ref() else {
            return false;
        };
        let mut h = handle;
        let write = (|| -> std::io::Result<()> {
            h.write_all(line.as_bytes())?;
            h.write_all(b"\n")?;
            h.flush()
        })();
        write.is_ok()
    }
}

/// File-open options shared by the scan path and the one-shot subcommands:
/// create-or-append, `0600` on Unix (the file names internal endpoints and
/// operator triage notes).
pub(crate) fn open_append(path: &str) -> std::io::Result<std::fs::File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Write the header when a brand-new file is opened by a one-shot subcommand.
/// Idempotent: callers only invoke it when the file did not exist.
pub(crate) fn write_header(file: &mut std::fs::File) -> std::io::Result<()> {
    let header = Header {
        dalfox_grouping: GROUPING_FORMAT_VERSION,
        version: env!("CARGO_PKG_VERSION").to_string(),
        created: chrono::Local::now().to_rfc3339(),
    };
    writeln!(file, "{}", serde_json::to_string(&header).unwrap_or_default())
}

/// Append a false-positive mark. Called by `dalfox findings mark-fp`.
pub(crate) fn append_false_positive(
    path: &str,
    entry_key: &str,
    note: Option<&str>,
) -> std::io::Result<FalsePositiveRecord> {
    let mut file = open_append(path)?;
    if file.metadata()?.len() == 0 {
        write_header(&mut file)?;
    }
    let record = FalsePositiveRecord {
        entry_key: entry_key.to_string(),
        marked_at: chrono::Local::now().to_rfc3339(),
        note: note.unwrap_or("").to_string(),
        fp_repeat_hits: 0,
        last_repeat_hit: None,
        removed: false,
    };
    writeln!(
        file,
        "{}",
        serde_json::to_string(&Row::FalsePositive(record.clone())).unwrap_or_default()
    )?;
    file.flush()?;
    Ok(record)
}

/// Append a false-positive removal as a tombstone row rather than rewriting the
/// file, keeping it append-only; [`GroupingStore::load`] honors `removed` and
/// drops the mark while the row stays as an audit trail. The `removed_at`
/// timestamp is an extra field readers without it simply ignore (these rows do
/// not use `deny_unknown_fields`).
pub(crate) fn append_false_positive_removal(
    path: &str,
    entry_key: &str,
    existing: &FalsePositiveRecord,
) -> std::io::Result<()> {
    let mut file = open_append(path)?;
    let row = FalsePositiveRecord {
        entry_key: entry_key.to_string(),
        marked_at: existing.marked_at.clone(),
        note: existing.note.clone(),
        fp_repeat_hits: existing.fp_repeat_hits,
        last_repeat_hit: existing.last_repeat_hit.clone(),
        removed: true,
    };
    #[derive(Serialize)]
    struct RemovalRow<'a> {
        kind: &'a str,
        entry_key: String,
        marked_at: String,
        note: String,
        fp_repeat_hits: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_repeat_hit: Option<String>,
        removed: bool,
        removed_at: String,
    }
    let removal = RemovalRow {
        kind: "false_positive",
        entry_key: row.entry_key,
        marked_at: row.marked_at,
        note: row.note,
        fp_repeat_hits: row.fp_repeat_hits,
        last_repeat_hit: row.last_repeat_hit,
        removed: true,
        removed_at: chrono::Local::now().to_rfc3339(),
    };
    writeln!(file, "{}", serde_json::to_string(&removal).unwrap_or_default())?;
    file.flush()
}

#[cfg(test)]
mod tests;
