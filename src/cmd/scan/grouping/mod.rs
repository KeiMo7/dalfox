//! `--group-by-injection-point`: organize a flat finding list into
//! injection-point groups with per-parameter verification states, and carry
//! false-positive marks and cross-run history through an optional JSONL
//! grouping file.
//!
//! Layers:
//! - [`identity`] — stable, payload- and time-invariant injection-point keys
//!   plus the verified / suspected / unverified vocabulary (pure functions).
//! - [`store`] — append-only JSONL persistence (false positives + history).
//! - [`aggregate`] — the single-pass, memory-bounded grouping engine.
//! - [`render`] — grouped renderers for plain / json / jsonl / markdown / toml.
//!
//! The feature is strictly opt-in. With neither `--group-by-injection-point`
//! nor `--grouping-file` set, none of this code runs and the output is
//! byte-for-byte unchanged.

mod action;
mod aggregate;
mod identity;
mod render;
mod store;

pub(crate) use action::{FindingsAction, run_findings_action};
pub(crate) use aggregate::aggregate;
pub(crate) use render::{
    grouped_json_envelope, grouped_markdown, grouped_plain, grouped_toml, render_grouped_jsonl,
};
pub(crate) use store::GroupingStore;

