//! Checkout / diff / flush — round-trip a facet subtree to disk as markdown.
//!
//! Three operations:
//! * [`checkout`] — write a subtree under `base_path` as nested `.md` files
//!   plus a `.trak/manifest.json` recording each facet's `updated_at` at
//!   checkout time so we can later detect concurrent server-side edits.
//! * [`diff`] — compare the working directory against the manifest + store
//!   and yield [`DiffEntry`] values describing creates, modifies, deletes,
//!   moves, and conflicts.
//! * [`flush`] — apply all on-disk changes back into the store. Conflicts
//!   are reported (and skipped) unless `force=true`.
//!
//! Filesystem layout (slugged ticket id or title):
//!
//! ```text
//! base_path/
//! ├── .trak/manifest.json
//! ├── trak-srp.md             ← root
//! └── trak-srp/               ← children of root
//!     ├── srp-1.md
//!     └── srp-2/
//!         └── sub.md
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::store::{FacetStore, StoreError};
use crate::types::{Facet, FacetMeta};

// ─── Public types ────────────────────────────────────────────────────

/// Manifest written into `.trak/manifest.json` at checkout time. Records
/// each facet's `updated_at` so [`flush`] can detect concurrent edits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub checkout_root: Uuid,
    pub checkout_at: DateTime<Utc>,
    pub facets: BTreeMap<Uuid, ManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Forward-slash path, relative to `base_path`.
    pub path: String,
    /// Server's `updated_at` at the time of checkout.
    pub checkout_updated_at: DateTime<Utc>,
    /// Server's `parent_id` at the time of checkout (for move detection).
    pub checkout_parent_id: Option<Uuid>,
}

/// One entry in the diff between disk and the store.
#[derive(Debug, Clone)]
pub enum DiffEntry {
    /// New file on disk that has no UUID in the manifest.
    Created { path: String, parsed: ParsedFacet },
    /// Known facet whose disk content differs from its store value.
    Modified {
        uuid: Uuid,
        path: String,
        parsed: ParsedFacet,
        original: Box<Facet>,
    },
    /// Known facet whose file is missing from disk.
    Deleted { uuid: Uuid, path: String },
    /// Known facet that moved to a different parent on disk.
    Moved {
        uuid: Uuid,
        old_path: String,
        new_path: String,
        new_parent: Option<Uuid>,
    },
    /// Server's `updated_at` is newer than the manifest's snapshot.
    Conflict { uuid: Uuid, reason: String },
}

impl DiffEntry {
    pub fn kind(&self) -> &'static str {
        match self {
            DiffEntry::Created { .. } => "created",
            DiffEntry::Modified { .. } => "modified",
            DiffEntry::Deleted { .. } => "deleted",
            DiffEntry::Moved { .. } => "moved",
            DiffEntry::Conflict { .. } => "conflict",
        }
    }

    pub fn path(&self) -> &str {
        match self {
            DiffEntry::Created { path, .. } => path,
            DiffEntry::Modified { path, .. } => path,
            DiffEntry::Deleted { path, .. } => path,
            DiffEntry::Moved { new_path, .. } => new_path,
            DiffEntry::Conflict { reason, .. } => reason,
        }
    }

    pub fn uuid(&self) -> Option<Uuid> {
        match self {
            DiffEntry::Created { .. } => None,
            DiffEntry::Modified { uuid, .. } => Some(*uuid),
            DiffEntry::Deleted { uuid, .. } => Some(*uuid),
            DiffEntry::Moved { uuid, .. } => Some(*uuid),
            DiffEntry::Conflict { uuid, .. } => Some(*uuid),
        }
    }
}

/// A facet parsed from a markdown file on disk.
#[derive(Debug, Clone)]
pub struct ParsedFacet {
    pub id: Option<Uuid>,
    pub parent_id_hint: Option<Uuid>,
    pub title: String,
    pub body: String,
    pub status: String,
    pub labels: Vec<String>,
    /// Unknown frontmatter keys, preserved verbatim into `meta.extra`.
    pub extras: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FlushReport {
    pub created: u32,
    pub modified: u32,
    pub deleted: u32,
    pub moved: u32,
    pub conflicts: Vec<DiffSummary>,
}

/// Lightweight summary used inside [`FlushReport`] (no Box<Facet>).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub kind: String,
    pub path: String,
    pub uuid: Option<Uuid>,
    pub detail: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum CheckoutError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("base path is not empty: {0}")]
    NotEmpty(String),
    #[error("missing manifest at {0}")]
    MissingManifest(String),
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("parse error at {path}: {message}")]
    Parse { path: String, message: String },
    #[error("store error: {0}")]
    Store(#[from] StoreError),
}

// ─── Public API ──────────────────────────────────────────────────────

/// Write the subtree rooted at `root_id` under `base_path` as markdown
/// files plus `.trak/manifest.json`.
///
/// Fails if `base_path` exists and contains anything (no implicit overwrite).
pub async fn checkout(
    store: &dyn FacetStore,
    root_id: Uuid,
    base_path: &Path,
) -> Result<Manifest, CheckoutError> {
    // Ensure base_path is empty (or doesn't exist).
    if base_path.exists() {
        let mut entries = std::fs::read_dir(base_path).map_err(|e| CheckoutError::Io {
            path: base_path.display().to_string(),
            source: e,
        })?;
        if entries.next().is_some() {
            return Err(CheckoutError::NotEmpty(base_path.display().to_string()));
        }
    } else {
        std::fs::create_dir_all(base_path).map_err(|e| CheckoutError::Io {
            path: base_path.display().to_string(),
            source: e,
        })?;
    }

    let subtree = store.get_subtree(root_id).await?;
    if subtree.is_empty() {
        return Err(CheckoutError::Store(StoreError::NotFound(root_id)));
    }

    // Build facet_id -> facet map for parent lookups.
    let by_id: BTreeMap<Uuid, Facet> = subtree
        .iter()
        .map(|(f, _)| (f.id, f.clone()))
        .collect();

    // Build facet_id -> directory PathBuf and facet_id -> file PathBuf.
    // The root sits directly under base_path. A facet with children also
    // gets a sibling directory `<slug>/` to hold them.
    //
    // We process in depth order so parents are placed first.
    let mut sorted: Vec<&(Facet, u32)> = subtree.iter().collect();
    sorted.sort_by_key(|(_, depth)| *depth);

    // dir_for[id] = directory in which this facet's .md file lives.
    let mut dir_for: BTreeMap<Uuid, PathBuf> = BTreeMap::new();
    // file_for[id] = absolute path to this facet's .md file.
    let mut file_for: BTreeMap<Uuid, PathBuf> = BTreeMap::new();
    // slug uniqueness within a directory.
    let mut used_slugs: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();

    for (facet, _depth) in &sorted {
        let parent_dir = match facet.parent_id {
            None => base_path.to_path_buf(),
            Some(pid) => match dir_for.get(&pid) {
                Some(parent_root) => {
                    // Children of `pid` live in `<parent_root>/<parent_slug>/`.
                    let parent_slug = file_for
                        .get(&pid)
                        .and_then(|p| p.file_stem())
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    parent_root.join(parent_slug)
                }
                None => base_path.to_path_buf(),
            },
        };

        let used = used_slugs.entry(parent_dir.clone()).or_default();
        let slug = unique_slug(&facet.title, used);
        used.insert(slug.clone());

        std::fs::create_dir_all(&parent_dir).map_err(|e| CheckoutError::Io {
            path: parent_dir.display().to_string(),
            source: e,
        })?;
        let file_path = parent_dir.join(format!("{slug}.md"));

        dir_for.insert(facet.id, parent_dir.clone());
        file_for.insert(facet.id, file_path.clone());

        // Render and write.
        let parent_id = by_id.get(&facet.id).and_then(|f| f.parent_id);
        let contents = render_markdown(facet, parent_id);
        write_atomic(&file_path, &contents)?;
    }

    // Build manifest.
    let now = Utc::now();
    let mut entries: BTreeMap<Uuid, ManifestEntry> = BTreeMap::new();
    for (facet, _depth) in &sorted {
        let abs = file_for
            .get(&facet.id)
            .ok_or_else(|| CheckoutError::Parse {
                path: facet.id.to_string(),
                message: "missing path in checkout map".into(),
            })?;
        let rel = abs
            .strip_prefix(base_path)
            .map_err(|_| CheckoutError::Parse {
                path: abs.display().to_string(),
                message: "path not under base_path".into(),
            })?;
        let rel_str = path_to_forward_slash(rel);
        entries.insert(
            facet.id,
            ManifestEntry {
                path: rel_str,
                checkout_updated_at: facet.updated_at,
                checkout_parent_id: facet.parent_id,
            },
        );
    }

    let manifest = Manifest {
        checkout_root: root_id,
        checkout_at: now,
        facets: entries,
    };

    write_manifest(base_path, &manifest)?;
    Ok(manifest)
}

/// Compute the diff between disk and the store, given an existing manifest.
pub async fn diff(
    store: &dyn FacetStore,
    base_path: &Path,
) -> Result<Vec<DiffEntry>, CheckoutError> {
    let manifest = read_manifest(base_path)?;

    // Walk all .md files under base_path (excluding .trak/).
    let mut on_disk = walk_markdown(base_path)?;
    on_disk.sort();

    // Index manifest by uuid → entry, plus by path → uuid for lookups.
    let path_to_uuid: BTreeMap<String, Uuid> = manifest
        .facets
        .iter()
        .map(|(u, e)| (e.path.clone(), *u))
        .collect();

    let mut seen_uuids: BTreeSet<Uuid> = BTreeSet::new();
    let mut diffs: Vec<DiffEntry> = Vec::new();

    for abs in &on_disk {
        let rel = abs
            .strip_prefix(base_path)
            .map_err(|_| CheckoutError::Parse {
                path: abs.display().to_string(),
                message: "path not under base_path".into(),
            })?;
        let rel_str = path_to_forward_slash(rel);

        let contents = std::fs::read_to_string(abs).map_err(|e| CheckoutError::Io {
            path: abs.display().to_string(),
            source: e,
        })?;
        let parsed = parse_markdown(&contents).map_err(|m| CheckoutError::Parse {
            path: abs.display().to_string(),
            message: m,
        })?;

        // Determine actual filesystem parent (UUID) — this is the source
        // of truth for hierarchy on flush.
        let fs_parent =
            fs_parent_uuid(abs, base_path, &manifest)?;

        match parsed.id {
            Some(uuid) => {
                seen_uuids.insert(uuid);

                // Lookup current store state.
                let original = match store.get_facet(uuid).await {
                    Ok(f) => f,
                    Err(StoreError::NotFound(_)) => {
                        // Manifest references a facet the store no longer has.
                        // Treat as deleted server-side; surface conflict.
                        diffs.push(DiffEntry::Conflict {
                            uuid,
                            reason: format!("facet {uuid} no longer in store"),
                        });
                        continue;
                    }
                    Err(e) => return Err(CheckoutError::Store(e)),
                };

                // Conflict check: server updated_at > manifest snapshot?
                let manifest_entry = manifest.facets.get(&uuid);
                if let Some(me) = manifest_entry {
                    if original.updated_at != me.checkout_updated_at {
                        diffs.push(DiffEntry::Conflict {
                            uuid,
                            reason: format!(
                                "server updated_at={} differs from checkout snapshot={}",
                                original.updated_at, me.checkout_updated_at
                            ),
                        });
                        continue;
                    }
                }

                // Move detection: did file path differ from manifest, or
                // does the filesystem parent differ from the stored parent?
                let manifest_path = manifest_entry.map(|me| me.path.clone());
                let path_changed = manifest_path
                    .as_ref()
                    .is_some_and(|mp| mp != &rel_str);
                let parent_changed = fs_parent != original.parent_id;

                if path_changed || parent_changed {
                    diffs.push(DiffEntry::Moved {
                        uuid,
                        old_path: manifest_path.unwrap_or_default(),
                        new_path: rel_str.clone(),
                        new_parent: fs_parent,
                    });
                }

                // Modified content?
                if facet_differs(&original, &parsed) {
                    diffs.push(DiffEntry::Modified {
                        uuid,
                        path: rel_str,
                        parsed,
                        original: Box::new(original),
                    });
                }
            }
            None => {
                // No id → either truly new, or an unknown old path that
                // happens not to map. Treat as Created.
                if path_to_uuid.contains_key(&rel_str) {
                    // Path matches a manifest entry but file lacks id —
                    // treat as Created (user removed the id).
                }
                diffs.push(DiffEntry::Created {
                    path: rel_str,
                    parsed,
                });
            }
        }
    }

    // Anything in manifest that wasn't seen on disk = deleted.
    for (uuid, entry) in &manifest.facets {
        if !seen_uuids.contains(uuid) {
            diffs.push(DiffEntry::Deleted {
                uuid: *uuid,
                path: entry.path.clone(),
            });
        }
    }

    Ok(diffs)
}

/// Apply all on-disk changes back into the store.
///
/// If a [`DiffEntry::Conflict`] is detected and `force=false`, the
/// conflict is added to the report and the change is *not* applied.
/// With `force=true`, the conflict is applied (overwriting server state).
pub async fn flush(
    store: &dyn FacetStore,
    base_path: &Path,
    owner: &str,
    force: bool,
) -> Result<FlushReport, CheckoutError> {
    let manifest = read_manifest(base_path)?;
    let diffs = diff(store, base_path).await?;

    let mut report = FlushReport::default();

    // Index conflicts by uuid for skip logic.
    let mut conflicted: BTreeSet<Uuid> = BTreeSet::new();
    if !force {
        for d in &diffs {
            if let DiffEntry::Conflict { uuid, .. } = d {
                conflicted.insert(*uuid);
            }
        }
    }

    for d in &diffs {
        match d {
            DiffEntry::Conflict { uuid, reason } => {
                if force {
                    // Reload and overwrite using current disk state.
                    if let Some(me) = manifest.facets.get(uuid) {
                        let abs = base_path.join(&me.path);
                        if let Ok(contents) = std::fs::read_to_string(&abs) {
                            if let Ok(parsed) = parse_markdown(&contents) {
                                if let Ok(mut current) = store.get_facet(*uuid).await {
                                    apply_parsed_to_facet(&mut current, &parsed);
                                    current.updated_at = Utc::now();
                                    if store.update_facet(&current).await.is_ok() {
                                        report.modified += 1;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    report.conflicts.push(DiffSummary {
                        kind: "conflict".into(),
                        path: manifest
                            .facets
                            .get(uuid)
                            .map(|e| e.path.clone())
                            .unwrap_or_default(),
                        uuid: Some(*uuid),
                        detail: Some(reason.clone()),
                    });
                }
            }
            DiffEntry::Created { path, parsed } => {
                let abs = base_path.join(path);
                let fs_parent = fs_parent_uuid(&abs, base_path, &manifest)?;
                let now = Utc::now();
                let mut meta = FacetMeta::default();
                if !parsed.labels.is_empty() {
                    meta.tags = Some(parsed.labels.clone());
                }
                for (k, v) in &parsed.extras {
                    meta.extra.insert(k.clone(), v.clone());
                }
                let new_id = parsed.id.unwrap_or_else(Uuid::new_v4);
                let facet = Facet {
                    id: new_id,
                    parent_id: fs_parent.or(parsed.parent_id_hint),
                    title: parsed.title.clone(),
                    body: if parsed.body.is_empty() {
                        None
                    } else {
                        Some(parsed.body.clone())
                    },
                    status: parsed.status.clone(),
                    owner: owner.to_string(),
                    meta,
                    created_at: now,
                    updated_at: now,
                };
                if store.create_facet(&facet).await.is_ok() {
                    report.created += 1;
                }
            }
            DiffEntry::Modified { uuid, parsed, .. } => {
                if conflicted.contains(uuid) {
                    continue;
                }
                if let Ok(mut current) = store.get_facet(*uuid).await {
                    apply_parsed_to_facet(&mut current, parsed);
                    current.updated_at = Utc::now();
                    if store.update_facet(&current).await.is_ok() {
                        report.modified += 1;
                    }
                }
            }
            DiffEntry::Moved {
                uuid, new_parent, ..
            } => {
                if conflicted.contains(uuid) {
                    continue;
                }
                if store.move_facet(*uuid, *new_parent).await.is_ok() {
                    report.moved += 1;
                }
            }
            DiffEntry::Deleted { uuid, .. } => {
                if conflicted.contains(uuid) {
                    continue;
                }
                if store.delete_facet(*uuid).await.is_ok() {
                    report.deleted += 1;
                }
            }
        }
    }

    Ok(report)
}

// ─── Markdown rendering ──────────────────────────────────────────────

fn render_markdown(facet: &Facet, parent_id: Option<Uuid>) -> String {
    let mut out = String::new();
    out.push_str("---\n");
    out.push_str(&format!("id: {}\n", facet.id));
    if let Some(p) = parent_id {
        out.push_str(&format!("parent_id: {p}\n"));
    }
    out.push_str(&format!("status: {}\n", facet.status));
    if let Some(tags) = &facet.meta.tags {
        if !tags.is_empty() {
            out.push_str(&format!("labels: [{}]\n", tags.join(", ")));
        }
    }
    // Preserve unknown extras (skip the keys we already serialized).
    for (k, v) in &facet.meta.extra {
        if k == "id" || k == "parent_id" || k == "status" || k == "labels" || k == "title" {
            continue;
        }
        out.push_str(&format!("{k}: {}\n", value_to_yaml(v)));
    }
    out.push_str("---\n");
    out.push_str(&format!("# {}\n", facet.title));
    if let Some(body) = &facet.body {
        if !body.is_empty() {
            out.push('\n');
            out.push_str(body.trim_end());
            out.push('\n');
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn value_to_yaml(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".into(),
        serde_json::Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(value_to_yaml).collect();
            format!("[{}]", parts.join(", "))
        }
        serde_json::Value::Object(_) => v.to_string(),
    }
}

// ─── Markdown parsing ────────────────────────────────────────────────

/// Parse a markdown file with optional frontmatter into a [`ParsedFacet`].
pub fn parse_markdown(content: &str) -> Result<ParsedFacet, String> {
    let mut id: Option<Uuid> = None;
    let mut parent_id_hint: Option<Uuid> = None;
    let mut status = "open".to_string();
    let mut labels: Vec<String> = Vec::new();
    let mut extras: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let mut frontmatter_title: Option<String> = None;

    let body_text;
    if content.starts_with("---") {
        let parts: Vec<&str> = content.splitn(3, "---").collect();
        if parts.len() < 3 {
            return Err("malformed frontmatter".into());
        }
        let frontmatter = parts[1];
        body_text = parts[2].trim_start_matches('\n').to_string();

        for line in frontmatter.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = match line.split_once(':') {
                Some(kv) => kv,
                None => continue,
            };
            let key = k.trim();
            let val = v.trim().trim_matches('"').trim_matches('\'');
            match key {
                "id" => {
                    id = Some(Uuid::parse_str(val).map_err(|e| format!("bad id: {e}"))?);
                }
                "parent_id" => {
                    if !val.is_empty() && val != "null" {
                        parent_id_hint =
                            Some(Uuid::parse_str(val).map_err(|e| format!("bad parent_id: {e}"))?);
                    }
                }
                "status" => status = val.to_string(),
                "labels" | "tags" => {
                    labels = parse_bracket_list(val);
                }
                "title" => frontmatter_title = Some(val.to_string()),
                other => {
                    extras.insert(
                        other.to_string(),
                        serde_json::Value::String(val.to_string()),
                    );
                }
            }
        }
    } else {
        body_text = content.to_string();
    }

    // Extract title from first H1; everything after H1 is the body.
    let (title, body) = split_title_and_body(&body_text);
    let title = title.or(frontmatter_title).unwrap_or_default();
    if title.is_empty() {
        return Err("missing title (no H1 heading found)".into());
    }

    Ok(ParsedFacet {
        id,
        parent_id_hint,
        title,
        body,
        status,
        labels,
        extras,
    })
}

/// Split body text on the first `# ` line; returns (title, remainder).
fn split_title_and_body(text: &str) -> (Option<String>, String) {
    let mut title: Option<String> = None;
    let mut body_lines: Vec<&str> = Vec::new();
    let mut found_h1 = false;

    for line in text.lines() {
        if !found_h1 {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("# ") {
                title = Some(rest.trim().to_string());
                found_h1 = true;
                continue;
            }
            // Skip leading blank lines before H1.
            if line.trim().is_empty() {
                continue;
            }
            // Non-blank, non-H1 line before any H1 → no title here.
            // Treat whole text as body.
            return (None, text.trim().to_string());
        }
        body_lines.push(line);
    }

    let body = body_lines.join("\n").trim().to_string();
    (title, body)
}

fn parse_bracket_list(val: &str) -> Vec<String> {
    let val = val.trim();
    let inner = val
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(val);

    if inner.trim().is_empty() {
        return Vec::new();
    }
    inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ─── Manifest I/O ────────────────────────────────────────────────────

fn manifest_path(base: &Path) -> PathBuf {
    base.join(".trak").join("manifest.json")
}

fn write_manifest(base: &Path, manifest: &Manifest) -> Result<(), CheckoutError> {
    let path = manifest_path(base);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CheckoutError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    let json =
        serde_json::to_string_pretty(manifest).map_err(|e| CheckoutError::InvalidManifest(e.to_string()))?;
    write_atomic(&path, &json)
}

fn read_manifest(base: &Path) -> Result<Manifest, CheckoutError> {
    let path = manifest_path(base);
    if !path.exists() {
        return Err(CheckoutError::MissingManifest(path.display().to_string()));
    }
    let s = std::fs::read_to_string(&path).map_err(|e| CheckoutError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    serde_json::from_str(&s).map_err(|e| CheckoutError::InvalidManifest(e.to_string()))
}

fn write_atomic(path: &Path, contents: &str) -> Result<(), CheckoutError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CheckoutError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).map_err(|e| CheckoutError::Io {
        path: tmp.display().to_string(),
        source: e,
    })?;
    std::fs::rename(&tmp, path).map_err(|e| CheckoutError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

// ─── Filesystem helpers ──────────────────────────────────────────────

fn walk_markdown(base: &Path) -> Result<Vec<PathBuf>, CheckoutError> {
    let mut out = Vec::new();
    walk_recursive(base, base, &mut out)?;
    Ok(out)
}

fn walk_recursive(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CheckoutError> {
    let entries = std::fs::read_dir(dir).map_err(|e| CheckoutError::Io {
        path: dir.display().to_string(),
        source: e,
    })?;
    for e in entries.flatten() {
        let path = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            // Skip .trak and any other dot dir/file.
            continue;
        }
        if path.is_dir() {
            walk_recursive(base, &path, out)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("md") {
            out.push(path);
        }
    }
    Ok(())
}

/// Determine the parent UUID for a file given its filesystem location.
///
/// The parent is whichever facet's `.md` file shares the parent directory's
/// stem name. If the file lives directly under `base_path`, it's a root.
fn fs_parent_uuid(
    file_abs: &Path,
    base_path: &Path,
    manifest: &Manifest,
) -> Result<Option<Uuid>, CheckoutError> {
    let parent_dir = match file_abs.parent() {
        Some(p) => p,
        None => return Ok(None),
    };

    // If the parent dir IS base_path, the file is a root.
    if parent_dir == base_path {
        return Ok(None);
    }

    // Parent dir's name (e.g. "trak-srp"). The facet whose .md sits next to
    // this dir (with the same stem) is the parent.
    let dir_name = match parent_dir.file_name() {
        Some(n) => n.to_string_lossy().into_owned(),
        None => return Ok(None),
    };
    let grandparent = match parent_dir.parent() {
        Some(p) => p,
        None => return Ok(None),
    };
    let candidate = grandparent.join(format!("{dir_name}.md"));

    // Look up by reading the candidate file's id; or by manifest path.
    if candidate.exists() {
        if let Ok(s) = std::fs::read_to_string(&candidate) {
            if let Ok(parsed) = parse_markdown(&s) {
                if let Some(id) = parsed.id {
                    return Ok(Some(id));
                }
            }
        }
    }

    // Fallback: search manifest for an entry whose path matches.
    let candidate_rel = candidate
        .strip_prefix(base_path)
        .map(path_to_forward_slash)
        .unwrap_or_default();
    for (uuid, entry) in &manifest.facets {
        if entry.path == candidate_rel {
            return Ok(Some(*uuid));
        }
    }
    Ok(None)
}

fn path_to_forward_slash(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

// ─── Diff helpers ────────────────────────────────────────────────────

fn facet_differs(original: &Facet, parsed: &ParsedFacet) -> bool {
    if original.title != parsed.title {
        return true;
    }
    if original.status != parsed.status {
        return true;
    }
    let body_now = original.body.clone().unwrap_or_default();
    let body_parsed = parsed.body.clone();
    if body_now.trim() != body_parsed.trim() {
        return true;
    }
    let tags_now: Vec<String> = original.meta.tags.clone().unwrap_or_default();
    if tags_now != parsed.labels {
        return true;
    }
    false
}

fn apply_parsed_to_facet(facet: &mut Facet, parsed: &ParsedFacet) {
    facet.title = parsed.title.clone();
    facet.status = parsed.status.clone();
    facet.body = if parsed.body.is_empty() {
        None
    } else {
        Some(parsed.body.clone())
    };
    if !parsed.labels.is_empty() {
        facet.meta.tags = Some(parsed.labels.clone());
    } else {
        facet.meta.tags = None;
    }
    for (k, v) in &parsed.extras {
        facet.meta.extra.insert(k.clone(), v.clone());
    }
}

// ─── Slug helpers ────────────────────────────────────────────────────

/// Build a unique slug from a title, ensuring no collision in `used`.
fn unique_slug(title: &str, used: &BTreeSet<String>) -> String {
    let base = slugify(title);
    if !used.contains(&base) {
        return base;
    }
    for n in 2..=9999 {
        let candidate = format!("{base}-{n}");
        if !used.contains(&candidate) {
            return candidate;
        }
    }
    // Pathological fallback.
    format!("{base}-{}", Uuid::new_v4().simple())
}

/// Build a slug from a facet title.
///
/// If the title matches `^([A-Z][A-Z0-9-]+):` (a ticket id prefix),
/// use just the ID prefix lowercased. Otherwise slugify the whole title.
fn slugify(title: &str) -> String {
    let re = Regex::new(r"^([A-Z][A-Z0-9-]+):").unwrap();
    if let Some(caps) = re.captures(title) {
        if let Some(m) = caps.get(1) {
            return slug_clean(m.as_str());
        }
    }
    slug_clean(title)
}

fn slug_clean(s: &str) -> String {
    let lower = s.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut last_dash = false;
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "facet".into()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_ticket_id_prefix() {
        assert_eq!(slugify("TRAK-SRP: SRP-6a Identity"), "trak-srp");
        assert_eq!(slugify("MFORGE-3: Per-Provider"), "mforge-3");
    }

    #[test]
    fn slug_plain_title() {
        assert_eq!(slugify("Hello World"), "hello-world");
        assert_eq!(slugify("Fix the !@# bug"), "fix-the-bug");
    }

    #[test]
    fn slug_collapse_repeats() {
        assert_eq!(slug_clean("foo----bar"), "foo-bar");
        assert_eq!(slug_clean("--leading"), "leading");
    }

    #[test]
    fn parse_basic_frontmatter() {
        let content = "---\nid: 778a0300-a574-48b0-82da-e215ac9d1d6e\nstatus: open\nlabels: [task, backend]\n---\n# Title\n\nBody here.\n";
        let p = parse_markdown(content).unwrap();
        assert_eq!(p.title, "Title");
        assert_eq!(p.status, "open");
        assert_eq!(p.labels, vec!["task", "backend"]);
        assert!(p.body.contains("Body here"));
    }

    #[test]
    fn parse_no_frontmatter() {
        let content = "# Just a title\n\nbody";
        let p = parse_markdown(content).unwrap();
        assert_eq!(p.title, "Just a title");
        assert_eq!(p.body, "body");
        assert!(p.id.is_none());
    }

    #[test]
    fn render_then_parse_roundtrip() {
        let now = Utc::now();
        let mut meta = FacetMeta::default();
        meta.tags = Some(vec!["task".into(), "alpha".into()]);
        let f = Facet {
            id: Uuid::new_v4(),
            parent_id: None,
            title: "Hello".into(),
            body: Some("Some body text".into()),
            status: "open".into(),
            owner: "u".into(),
            meta,
            created_at: now,
            updated_at: now,
        };
        let md = render_markdown(&f, None);
        let parsed = parse_markdown(&md).unwrap();
        assert_eq!(parsed.id, Some(f.id));
        assert_eq!(parsed.title, "Hello");
        assert_eq!(parsed.status, "open");
        assert_eq!(parsed.labels, vec!["task", "alpha"]);
        assert_eq!(parsed.body, "Some body text");
    }
}
