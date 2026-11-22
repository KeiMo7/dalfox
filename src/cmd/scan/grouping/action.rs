//! One-shot `dalfox findings …` actions: mutate the grouping file without
//! running a scan. Kept separate from the scan path so triage never sends HTTP
//! traffic and works against a file produced by any earlier grouped run.

use super::store::{
    GroupingStore, append_false_positive, append_false_positive_removal,
};

/// The two triage actions. Mirrors the clap enum in `main.rs`, which converts
/// into this type so the scan module's public surface stays free of clap.
#[derive(Debug, Clone)]
pub(crate) enum FindingsAction {
    MarkFp {
        grouping_file: String,
        entry_key: String,
        note: Option<String>,
    },
    UnmarkFp {
        grouping_file: String,
        entry_key: String,
    },
}

/// Execute a triage action. Returns the process outcome so `main` maps it to an
/// exit code the same way it does for scans.
pub(crate) async fn run_findings_action(action: FindingsAction) -> crate::cmd::scan::ScanOutcome {
    match action {
        FindingsAction::MarkFp {
            grouping_file,
            entry_key,
            note,
        } => {
            // A missing file is created with its header; an existing foreign or
            // corrupt file is refused rather than appending a mark a later scan
            // could not read back.
            let exists = std::path::Path::new(&grouping_file).exists();
            if exists {
                match GroupingStore::load_only(&grouping_file) {
                    Ok(store) => {
                        if let Some(warning) = &store.warning {
                            eprintln!("Error: {warning}");
                            return crate::cmd::scan::ScanOutcome::Error;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        return crate::cmd::scan::ScanOutcome::Error;
                    }
                }
            }
            match append_false_positive(
                &grouping_file,
                &entry_key,
                note.as_deref(),
            ) {
                Ok(_) => {
                    println!(
                        "Marked {} as false positive in {}",
                        entry_key, grouping_file
                    );
                    crate::cmd::scan::ScanOutcome::Clean
                }
                Err(e) => {
                    eprintln!("Error writing grouping file '{}': {}", grouping_file, e);
                    crate::cmd::scan::ScanOutcome::Error
                }
            }
        }
        FindingsAction::UnmarkFp {
            grouping_file,
            entry_key,
        } => {
            let store = match GroupingStore::load_only(&grouping_file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error: {e}");
                    return crate::cmd::scan::ScanOutcome::Error;
                }
            };
            let Some(record) = store.false_positive_record(&entry_key).cloned() else {
                eprintln!(
                    "Error: no active false-positive mark for {} in {}",
                    entry_key, grouping_file
                );
                return crate::cmd::scan::ScanOutcome::Error;
            };
            match append_false_positive_removal(&grouping_file, &entry_key, &record) {
                Ok(_) => {
                    println!(
                        "Cleared false-positive mark for {} in {} (record retained)",
                        entry_key, grouping_file
                    );
                    crate::cmd::scan::ScanOutcome::Clean
                }
                Err(e) => {
                    eprintln!("Error writing grouping file '{}': {}", grouping_file, e);
                    crate::cmd::scan::ScanOutcome::Error
                }
            }
        }
    }
}
