//! Import plan epics from the hypermemetic workspace into trak facets.
//!
//! Parses two markdown plan formats:
//!
//! Format A (frontmatter):
//! ```markdown
//! ---
//! id: SAFE-1
//! title: "SAFE — synapse-cc parity"
//! status: Epic
//! type: epic
//! blocked_by: []
//! unlocks: []
//! ---
//! ## Goal
//! ```
//!
//! Format B (inline):
//! ```markdown
//! # MFORGE-3: Per-Provider Credential Resolution
//!
//! blocked_by: [MFORGE-2]
//! unlocks: [MFORGE-5, MFORGE-6]
//!
//! ## Scope
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::types::{Edge, EdgeKind, Facet, FacetMeta};
use crate::store::FacetStore;

use chrono::Utc;
use uuid::Uuid;

/// A parsed plan ticket.
#[derive(Debug, Clone)]
pub struct ParsedTicket {
    /// The ticket ID from the filename or frontmatter (e.g. "MFORGE-3")
    pub id: String,
    /// Epic prefix (e.g. "MFORGE")
    pub epic: String,
    /// Title extracted from heading or frontmatter
    pub title: String,
    /// Body (everything after the metadata)
    pub body: String,
    /// Status if declared (from frontmatter `status:`)
    pub status: Option<String>,
    /// Type if declared (from frontmatter `type:`)
    pub ticket_type: Option<String>,
    /// Blocked-by references (e.g. ["MFORGE-2"])
    pub blocked_by: Vec<String>,
    /// Unlocks references (e.g. ["MFORGE-5", "MFORGE-6"])
    pub unlocks: Vec<String>,
    /// Source repo directory name
    pub repo: String,
    /// Source file path
    pub source_path: PathBuf,
}

/// Scan a workspace directory for plan files and parse them.
pub fn scan_plans(workspace_path: &Path) -> Vec<ParsedTicket> {
    let mut tickets = Vec::new();

    // Walk every repo dir looking for plans/
    let entries = match std::fs::read_dir(workspace_path) {
        Ok(e) => e,
        Err(_) => return tickets,
    };

    for entry in entries.flatten() {
        let repo_path = entry.path();
        if !repo_path.is_dir() {
            continue;
        }
        let repo_name = entry
            .file_name()
            .to_string_lossy()
            .into_owned();

        // Check plans/ and docs/plans/
        for plans_subdir in &["plans", "docs/plans"] {
            let plans_dir = repo_path.join(plans_subdir);
            if plans_dir.is_dir() {
                scan_plans_dir(&plans_dir, &repo_name, &mut tickets);
            }
        }
    }

    // Also check workspace-level plans/
    let ws_plans = workspace_path.join("plans");
    if ws_plans.is_dir() {
        scan_plans_dir(&ws_plans, "workspace", &mut tickets);
    }

    tickets
}

fn scan_plans_dir(plans_dir: &Path, repo_name: &str, tickets: &mut Vec<ParsedTicket>) {
    let entries = match std::fs::read_dir(plans_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Epic subdirectory (e.g. plans/MFORGE/)
            let epic_name = entry.file_name().to_string_lossy().into_owned();
            if let Ok(files) = std::fs::read_dir(&path) {
                for file in files.flatten() {
                    let file_path = file.path();
                    if file_path.extension().is_some_and(|e| e == "md") {
                        if let Some(ticket) = parse_plan_file(&file_path, &epic_name, repo_name) {
                            tickets.push(ticket);
                        }
                    }
                }
            }
        } else if path.extension().is_some_and(|e| e == "md") {
            // Top-level plan file
            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
            let epic = stem
                .split('-')
                .next()
                .unwrap_or(&stem)
                .to_string();
            if let Some(ticket) = parse_plan_file(&path, &epic, repo_name) {
                tickets.push(ticket);
            }
        }
    }
}

fn parse_plan_file(path: &Path, epic: &str, repo: &str) -> Option<ParsedTicket> {
    let content = std::fs::read_to_string(path).ok()?;
    let filename_stem = path
        .file_stem()?
        .to_string_lossy()
        .into_owned();

    // Skip artifact/checkpoint files
    if filename_stem.contains("CHECKPOINT")
        || filename_stem.contains("output")
        || filename_stem.contains("EVAL")
        || filename_stem.starts_with("artifacts")
    {
        return None;
    }

    // Try frontmatter format first
    if content.starts_with("---") {
        return parse_frontmatter(&content, epic, repo, path, &filename_stem);
    }

    // Try inline format
    parse_inline(&content, epic, repo, path, &filename_stem)
}

fn parse_frontmatter(
    content: &str,
    epic: &str,
    repo: &str,
    path: &Path,
    filename_stem: &str,
) -> Option<ParsedTicket> {
    // Split on --- delimiters
    let parts: Vec<&str> = content.splitn(3, "---").collect();
    if parts.len() < 3 {
        return None;
    }

    let frontmatter = parts[1];
    let body = parts[2].trim().to_string();

    let mut id = filename_stem.to_string();
    let mut title = String::new();
    let mut status = None;
    let mut ticket_type = None;
    let mut blocked_by = Vec::new();
    let mut unlocks = Vec::new();

    for line in frontmatter.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("id:") {
            id = val.trim().trim_matches('"').to_string();
        } else if let Some(val) = line.strip_prefix("title:") {
            title = val.trim().trim_matches('"').to_string();
        } else if let Some(val) = line.strip_prefix("status:") {
            status = Some(val.trim().trim_matches('"').to_lowercase());
        } else if let Some(val) = line.strip_prefix("type:") {
            ticket_type = Some(val.trim().trim_matches('"').to_lowercase());
        } else if let Some(val) = line.strip_prefix("blocked_by:") {
            blocked_by = parse_bracket_list(val);
        } else if let Some(val) = line.strip_prefix("unlocks:") {
            unlocks = parse_bracket_list(val);
        }
    }

    if title.is_empty() {
        // Try to get title from first heading in body
        title = extract_heading(&body).unwrap_or_else(|| id.clone());
    }

    Some(ParsedTicket {
        id,
        epic: epic.to_string(),
        title,
        body,
        status,
        ticket_type,
        blocked_by,
        unlocks,
        repo: repo.to_string(),
        source_path: path.to_path_buf(),
    })
}

fn parse_inline(
    content: &str,
    epic: &str,
    repo: &str,
    path: &Path,
    filename_stem: &str,
) -> Option<ParsedTicket> {
    let mut lines = content.lines();

    // First line should be a heading: # TICKET-ID: Title
    let first_line = lines.next()?.trim();
    let heading = first_line.strip_prefix('#')?.trim();

    let (id, title) = if let Some((id_part, title_part)) = heading.split_once(':') {
        (id_part.trim().to_string(), title_part.trim().to_string())
    } else {
        (filename_stem.to_string(), heading.to_string())
    };

    let mut blocked_by = Vec::new();
    let mut unlocks = Vec::new();
    let mut body_lines = Vec::new();
    let mut in_metadata = true;

    for line in lines {
        let trimmed = line.trim();

        if in_metadata {
            if let Some(val) = trimmed.strip_prefix("blocked_by:") {
                blocked_by = parse_bracket_list(val);
                continue;
            }
            if let Some(val) = trimmed.strip_prefix("unlocks:") {
                unlocks = parse_bracket_list(val);
                continue;
            }
            // Empty lines between heading and metadata are OK
            if trimmed.is_empty() {
                continue;
            }
            // First non-metadata line → switch to body
            in_metadata = false;
        }

        body_lines.push(line);
    }

    let body = body_lines.join("\n").trim().to_string();

    Some(ParsedTicket {
        id,
        epic: epic.to_string(),
        title,
        body,
        status: None,
        ticket_type: None,
        blocked_by,
        unlocks,
        repo: repo.to_string(),
        source_path: path.to_path_buf(),
    })
}

/// Parse `[FOO-1, FOO-2]` or `[FOO-1]` or `[]` into a Vec of strings.
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

fn extract_heading(body: &str) -> Option<String> {
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(heading) = trimmed.strip_prefix('#') {
            let heading = heading.trim_start_matches('#').trim();
            if !heading.is_empty() {
                return Some(heading.to_string());
            }
        }
    }
    None
}

/// Import parsed tickets into trak as facets.
///
/// Creates a hierarchy: repo → epic → ticket.
/// Wires up `blocked_by` as `depends_on` edges and `unlocks` as `blocks` edges.
pub async fn import_into_trak(
    store: &dyn FacetStore,
    tickets: &[ParsedTicket],
    owner: &str,
    tenant: Option<&str>,
) -> ImportReport {
    let mut report = ImportReport::default();
    let now = Utc::now();

    // Group by repo → epic
    let mut by_repo: HashMap<String, HashMap<String, Vec<&ParsedTicket>>> = HashMap::new();
    for ticket in tickets {
        by_repo
            .entry(ticket.repo.clone())
            .or_default()
            .entry(ticket.epic.clone())
            .or_default()
            .push(ticket);
    }

    // Track ticket_id → facet UUID for edge wiring
    let mut id_to_uuid: HashMap<String, Uuid> = HashMap::new();

    // Helper to build a FacetMeta with optional tags and extras
    let make_meta = |tags: Vec<String>, extras: serde_json::Map<String, serde_json::Value>| -> FacetMeta {
        FacetMeta {
            priority: None,
            tags: if tags.is_empty() { None } else { Some(tags) },
            extra: extras,
        }
    };

    // Phase 1: Create facets (repo → epic → ticket)
    for (repo_name, epics) in &by_repo {
        let repo_uuid = Uuid::new_v4();
        let mut extra = serde_json::Map::new();
        if let Some(t) = tenant {
            extra.insert("tenant".into(), serde_json::Value::String(t.to_string()));
        }

        let repo_facet = Facet {
            id: repo_uuid,
            parent_id: None,
            title: repo_name.clone(),
            body: None,
            status: "active".to_string(),
            owner: owner.to_string(),
            meta: make_meta(vec!["repo".into()], extra.clone()),
            created_at: now,
            updated_at: now,
        };

        if store.create_facet(&repo_facet).await.is_ok() {
            report.repos_created += 1;
        }

        for (epic_name, epic_tickets) in epics {
            let epic_overview = epic_tickets.iter().find(|t| {
                t.ticket_type.as_deref() == Some("epic")
                    || t.id.ends_with("-1")
                    || t.title.to_lowercase().contains("epic overview")
            });

            let epic_title = epic_overview
                .map(|t| format!("{}: {}", epic_name, t.title))
                .unwrap_or_else(|| epic_name.clone());

            let epic_body = epic_overview.map(|t| t.body.clone());
            let epic_status = epic_overview
                .and_then(|t| t.status.clone())
                .unwrap_or_else(|| "open".to_string());

            let epic_uuid = Uuid::new_v4();
            let epic_facet = Facet {
                id: epic_uuid,
                parent_id: Some(repo_uuid),
                title: epic_title,
                body: epic_body,
                status: epic_status,
                owner: owner.to_string(),
                meta: make_meta(vec!["epic".into()], extra.clone()),
                created_at: now,
                updated_at: now,
            };

            if store.create_facet(&epic_facet).await.is_ok() {
                report.epics_created += 1;
            }

            for ticket in epic_tickets {
                if epic_overview.is_some_and(|eo| std::ptr::eq(*eo, *ticket)) {
                    id_to_uuid.insert(ticket.id.clone(), epic_uuid);
                    continue;
                }

                let ticket_uuid = Uuid::new_v4();
                let ticket_status = ticket.status.clone().unwrap_or_else(|| "open".to_string());

                let mut tags = vec!["ticket".into()];
                if let Some(ref tt) = ticket.ticket_type {
                    tags.push(tt.clone());
                }

                let mut ticket_extra = extra.clone();
                ticket_extra.insert("source_path".into(), serde_json::Value::String(ticket.source_path.to_string_lossy().into_owned()));
                ticket_extra.insert("ticket_id".into(), serde_json::Value::String(ticket.id.clone()));
                ticket_extra.insert("epic".into(), serde_json::Value::String(ticket.epic.clone()));
                ticket_extra.insert("repo".into(), serde_json::Value::String(ticket.repo.clone()));

                let ticket_facet = Facet {
                    id: ticket_uuid,
                    parent_id: Some(epic_uuid),
                    title: format!("{}: {}", ticket.id, ticket.title),
                    body: Some(ticket.body.clone()),
                    status: ticket_status,
                    owner: owner.to_string(),
                    meta: make_meta(tags, ticket_extra),
                    created_at: now,
                    updated_at: now,
                };

                if store.create_facet(&ticket_facet).await.is_ok() {
                    report.tickets_created += 1;
                }

                id_to_uuid.insert(ticket.id.clone(), ticket_uuid);
            }
        }
    }

    // Phase 2: Wire edges from blocked_by / unlocks
    for ticket in tickets {
        let source_uuid = match id_to_uuid.get(&ticket.id) {
            Some(u) => *u,
            None => continue,
        };

        for dep_id in &ticket.blocked_by {
            if let Some(&target_uuid) = id_to_uuid.get(dep_id) {
                let edge = Edge {
                    from_id: source_uuid,
                    to_id: target_uuid,
                    kind: EdgeKind::DependsOn,
                    created_at: now,
                };
                if store.add_edge(&edge).await.is_ok() {
                    report.edges_created += 1;
                }
            }
        }

        for unlock_id in &ticket.unlocks {
            if let Some(&target_uuid) = id_to_uuid.get(unlock_id) {
                let edge = Edge {
                    from_id: source_uuid,
                    to_id: target_uuid,
                    kind: EdgeKind::Blocks,
                    created_at: now,
                };
                if store.add_edge(&edge).await.is_ok() {
                    report.edges_created += 1;
                }
            }
        }
    }

    report
}

#[derive(Debug, Default)]
pub struct ImportReport {
    pub repos_created: u32,
    pub epics_created: u32,
    pub tickets_created: u32,
    pub edges_created: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_parse_inline_format() {
        let content = r#"# MFORGE-3: Per-Provider Credential Resolution

blocked_by: [MFORGE-2]
unlocks: [MFORGE-5, MFORGE-6]

## Scope

Replace org-wide token_ref_for with provider-scoped variants.
"#;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("MFORGE-3.md");
        std::fs::write(&path, content).unwrap();

        let ticket = parse_plan_file(&path, "MFORGE", "hyperforge").unwrap();
        assert_eq!(ticket.id, "MFORGE-3");
        assert_eq!(ticket.title, "Per-Provider Credential Resolution");
        assert_eq!(ticket.blocked_by, vec!["MFORGE-2"]);
        assert_eq!(ticket.unlocks, vec!["MFORGE-5", "MFORGE-6"]);
        assert!(ticket.body.contains("Replace org-wide"));
    }

    #[test]
    fn test_parse_frontmatter_format() {
        let content = r#"---
id: SAFE-1
title: "SAFE — synapse-cc parity with current Plexus stack"
status: Epic
type: epic
blocked_by: []
unlocks: []
---

## Goal

Make synapse-cc match the current stack.
"#;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("SAFE-1.md");
        std::fs::write(&path, content).unwrap();

        let ticket = parse_plan_file(&path, "SAFE", "synapse-cc").unwrap();
        assert_eq!(ticket.id, "SAFE-1");
        assert_eq!(ticket.title, "SAFE — synapse-cc parity with current Plexus stack");
        assert_eq!(ticket.status, Some("epic".to_string()));
        assert_eq!(ticket.ticket_type, Some("epic".to_string()));
        assert!(ticket.blocked_by.is_empty());
    }

    #[test]
    fn test_parse_bracket_list() {
        assert_eq!(parse_bracket_list("[MFORGE-2]"), vec!["MFORGE-2"]);
        assert_eq!(
            parse_bracket_list("[MFORGE-5, MFORGE-6]"),
            vec!["MFORGE-5", "MFORGE-6"]
        );
        assert!(parse_bracket_list("[]").is_empty());
        assert_eq!(
            parse_bracket_list("[\"FOO-1\", \"FOO-2\"]"),
            vec!["FOO-1", "FOO-2"]
        );
    }

    #[test]
    fn test_scan_plans_structure() {
        let dir = TempDir::new().unwrap();

        // Create repo with plans/EPIC/ structure
        let epic_dir = dir.path().join("myrepo/plans/FEAT");
        std::fs::create_dir_all(&epic_dir).unwrap();

        let mut f = std::fs::File::create(epic_dir.join("FEAT-1.md")).unwrap();
        writeln!(f, "# FEAT-1: Epic Overview\n\nblocked_by: []\nunlocks: [FEAT-2]\n\n## Goal").unwrap();

        let mut f = std::fs::File::create(epic_dir.join("FEAT-2.md")).unwrap();
        writeln!(f, "# FEAT-2: Do the thing\n\nblocked_by: [FEAT-1]\nunlocks: []\n\n## Scope").unwrap();

        let tickets = scan_plans(dir.path());
        assert_eq!(tickets.len(), 2);
        assert!(tickets.iter().any(|t| t.id == "FEAT-1"));
        assert!(tickets.iter().any(|t| t.id == "FEAT-2"));
    }
}
