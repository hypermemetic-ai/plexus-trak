//! Integration tests that exercise the same workflows as the FacetHub,
//! operating directly on the FacetStore trait since the hub methods are
//! RPC-only (private, called via subscription sinks from the macro layer).
//!
//! These tests verify the composite operations that the hub performs:
//! create+get, update+get, delete+verify-gone, tree traversals,
//! edge management, blocked-detection logic, and full-text search.

use std::sync::Arc;

use chrono::Utc;
use plexus_trak::store::sqlite::SqliteStore;
use plexus_trak::store::{Direction, FacetStore};
use plexus_trak::types::{Edge, EdgeKind, Facet, FacetMeta};
use tempfile::TempDir;
use uuid::Uuid;

async fn temp_store() -> (Arc<SqliteStore>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("hub_test.db");
    let store = SqliteStore::new(db_path.to_str().unwrap()).await.unwrap();
    (Arc::new(store), dir)
}

fn make_facet(title: &str, parent_id: Option<Uuid>, owner: &str, status: &str) -> Facet {
    let now = Utc::now();
    Facet {
        id: Uuid::new_v4(),
        parent_id,
        title: title.to_string(),
        body: None,
        status: status.to_string(),
        owner: owner.to_string(),
        meta: FacetMeta::default(),
        created_at: now,
        updated_at: now,
    }
}

fn make_edge(from: Uuid, to: Uuid, kind: EdgeKind) -> Edge {
    Edge {
        from_id: from,
        to_id: to,
        kind,
        created_at: Utc::now(),
    }
}

// ── Create → Get roundtrip (mirrors hub.create + hub.get) ──────────

#[tokio::test]
async fn test_create_returns_facet() {
    let (store, _dir) = temp_store().await;

    let facet = make_facet("my task", None, "testuser", "open");
    store.create_facet(&facet).await.unwrap();

    let got = store.get_facet(facet.id).await.unwrap();
    assert_eq!(got.title, "my task");
    assert_eq!(got.status, "open");
    assert_eq!(got.owner, "testuser");
}

#[tokio::test]
async fn test_create_with_parent() {
    let (store, _dir) = temp_store().await;

    let parent = make_facet("parent", None, "user", "open");
    store.create_facet(&parent).await.unwrap();

    let child = make_facet("child", Some(parent.id), "user", "open");
    store.create_facet(&child).await.unwrap();

    let children = store.list_children(Some(parent.id)).await.unwrap();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].id, child.id);
}

// ── Update status (mirrors hub.update) ─────────────────────────────

#[tokio::test]
async fn test_update_status() {
    let (store, _dir) = temp_store().await;

    let mut facet = make_facet("to update", None, "user", "open");
    store.create_facet(&facet).await.unwrap();

    facet.status = "done".to_string();
    facet.updated_at = Utc::now();
    store.update_facet(&facet).await.unwrap();

    let got = store.get_facet(facet.id).await.unwrap();
    assert_eq!(got.status, "done");
    assert_eq!(got.title, "to update"); // unchanged
}

// ── Delete (mirrors hub.delete) ────────────────────────────────────

#[tokio::test]
async fn test_delete_parent_children_orphaned() {
    let (store, _dir) = temp_store().await;

    let parent = make_facet("parent", None, "user", "open");
    let child = make_facet("child", Some(parent.id), "user", "open");
    store.create_facet(&parent).await.unwrap();
    store.create_facet(&child).await.unwrap();

    store.delete_facet(parent.id).await.unwrap();

    // Parent gone
    assert!(store.get_facet(parent.id).await.is_err());

    // Child orphaned (ON DELETE SET NULL)
    let got_child = store.get_facet(child.id).await.unwrap();
    assert!(got_child.parent_id.is_none());
}

// ── List with status filter (hub.list emits FacetSummary events) ───

#[tokio::test]
async fn test_list_with_status_filter() {
    let (store, _dir) = temp_store().await;

    // Create 3 open + 2 done root facets
    for i in 0..3 {
        let f = make_facet(&format!("open-{i}"), None, "user", "open");
        store.create_facet(&f).await.unwrap();
    }
    for i in 0..2 {
        let f = make_facet(&format!("done-{i}"), None, "user", "done");
        store.create_facet(&f).await.unwrap();
    }

    let roots = store.list_roots().await.unwrap();
    assert_eq!(roots.len(), 5);

    // Filter by status (as the hub would do client-side)
    let open_facets: Vec<_> = roots.iter().filter(|f| f.status == "open").collect();
    assert_eq!(open_facets.len(), 3);

    let done_facets: Vec<_> = roots.iter().filter(|f| f.status == "done").collect();
    assert_eq!(done_facets.len(), 2);
}

// ── Tree recursive (mirrors hub.tree) ──────────────────────────────

#[tokio::test]
async fn test_tree_recursive() {
    let (store, _dir) = temp_store().await;

    let root = make_facet("root", None, "user", "open");
    let mid = make_facet("mid", Some(root.id), "user", "open");
    let leaf = make_facet("leaf", Some(mid.id), "user", "open");
    store.create_facet(&root).await.unwrap();
    store.create_facet(&mid).await.unwrap();
    store.create_facet(&leaf).await.unwrap();

    let tree = store.get_subtree(root.id).await.unwrap();
    assert_eq!(tree.len(), 3);

    // Verify depths
    let find_depth = |id: Uuid| tree.iter().find(|(f, _)| f.id == id).unwrap().1;
    assert_eq!(find_depth(root.id), 0);
    assert_eq!(find_depth(mid.id), 1);
    assert_eq!(find_depth(leaf.id), 2);

    // Verify child counts (as hub.tree does)
    for (facet, _depth) in &tree {
        let child_count = store.count_children(Some(facet.id)).await.unwrap();
        if facet.id == root.id {
            assert_eq!(child_count, 1);
        } else if facet.id == mid.id {
            assert_eq!(child_count, 1);
        } else {
            assert_eq!(child_count, 0);
        }
    }
}

// ── Link creates edge (mirrors hub.link) ───────────────────────────

#[tokio::test]
async fn test_link_creates_edge() {
    let (store, _dir) = temp_store().await;

    let a = make_facet("A", None, "user", "open");
    let b = make_facet("B", None, "user", "open");
    store.create_facet(&a).await.unwrap();
    store.create_facet(&b).await.unwrap();

    let edge = make_edge(a.id, b.id, EdgeKind::DependsOn);
    store.add_edge(&edge).await.unwrap();

    let edges = store
        .get_edges(a.id, Direction::Outgoing, None)
        .await
        .unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].to_id, b.id);
    assert_eq!(edges[0].kind, EdgeKind::DependsOn);
}

// ── Blocked detection (mirrors hub.blocked logic) ──────────────────

#[tokio::test]
async fn test_blocked_finds_dependent() {
    let (store, _dir) = temp_store().await;

    let a = make_facet("blocked task", None, "user", "open");
    let b = make_facet("blocker", None, "user", "open");
    store.create_facet(&a).await.unwrap();
    store.create_facet(&b).await.unwrap();

    // A depends_on B (B is open → A is blocked)
    let edge = make_edge(a.id, b.id, EdgeKind::DependsOn);
    store.add_edge(&edge).await.unwrap();

    // Replicate hub.blocked logic: list facets, check deps
    let facets = store.list_children(None).await.unwrap();
    let mut blocked_list = Vec::new();

    for facet in &facets {
        let deps = store
            .get_edges(facet.id, Direction::Outgoing, Some(&EdgeKind::DependsOn))
            .await
            .unwrap();
        let mut blockers = Vec::new();
        for dep in &deps {
            if let Ok(target) = store.get_facet(dep.to_id).await {
                if target.status != "done" {
                    blockers.push(dep.to_id);
                }
            }
        }
        if !blockers.is_empty() {
            blocked_list.push((facet.id, blockers));
        }
    }

    assert_eq!(blocked_list.len(), 1);
    assert_eq!(blocked_list[0].0, a.id);
    assert!(blocked_list[0].1.contains(&b.id));
}

#[tokio::test]
async fn test_blocked_resolved() {
    let (store, _dir) = temp_store().await;

    let a = make_facet("dependent", None, "user", "open");
    let mut b = make_facet("dependency", None, "user", "open");
    store.create_facet(&a).await.unwrap();
    store.create_facet(&b).await.unwrap();

    // A depends_on B
    let edge = make_edge(a.id, b.id, EdgeKind::DependsOn);
    store.add_edge(&edge).await.unwrap();

    // Mark B as done
    b.status = "done".to_string();
    b.updated_at = Utc::now();
    store.update_facet(&b).await.unwrap();

    // Replicate hub.blocked logic
    let facets = store.list_children(None).await.unwrap();
    let mut blocked_list = Vec::new();

    for facet in &facets {
        let deps = store
            .get_edges(facet.id, Direction::Outgoing, Some(&EdgeKind::DependsOn))
            .await
            .unwrap();
        let mut blockers = Vec::new();
        for dep in &deps {
            if let Ok(target) = store.get_facet(dep.to_id).await {
                if target.status != "done" {
                    blockers.push(dep.to_id);
                }
            }
        }
        if !blockers.is_empty() {
            blocked_list.push((facet.id, blockers));
        }
    }

    assert!(
        blocked_list.is_empty(),
        "A should not be blocked after B is done"
    );
}

// ── Search (mirrors hub.search) ────────────────────────────────────

#[tokio::test]
async fn test_search_finds_match() {
    let (store, _dir) = temp_store().await;

    let f1 = make_facet("deploy v5", None, "user", "open");
    let f2 = make_facet("deploy v6", None, "user", "open");
    let f3 = make_facet("fix bug", None, "user", "open");
    store.create_facet(&f1).await.unwrap();
    store.create_facet(&f2).await.unwrap();
    store.create_facet(&f3).await.unwrap();

    let results = store.search("deploy").await.unwrap();
    assert_eq!(results.len(), 2);
}

#[tokio::test]
async fn test_search_no_match() {
    let (store, _dir) = temp_store().await;

    let f = make_facet("hello world", None, "user", "open");
    store.create_facet(&f).await.unwrap();

    let results = store.search("nonexistent").await.unwrap();
    assert!(results.is_empty());
}

// ── Move → verify parent changes ──────────────────────────────────

#[tokio::test]
async fn test_move_reports_old_and_new_parent() {
    let (store, _dir) = temp_store().await;

    let parent_a = make_facet("parent A", None, "user", "open");
    let parent_b = make_facet("parent B", None, "user", "open");
    let child = make_facet("child", Some(parent_a.id), "user", "open");
    store.create_facet(&parent_a).await.unwrap();
    store.create_facet(&parent_b).await.unwrap();
    store.create_facet(&child).await.unwrap();

    // Record old parent (as hub.move_to does)
    let old_parent = store.get_facet(child.id).await.unwrap().parent_id;
    assert_eq!(old_parent, Some(parent_a.id));

    // Move
    store.move_facet(child.id, Some(parent_b.id)).await.unwrap();

    let got = store.get_facet(child.id).await.unwrap();
    assert_eq!(got.parent_id, Some(parent_b.id));
}

// ── Unlink (mirrors hub.unlink) ────────────────────────────────────

#[tokio::test]
async fn test_unlink() {
    let (store, _dir) = temp_store().await;

    let a = make_facet("A", None, "user", "open");
    let b = make_facet("B", None, "user", "open");
    store.create_facet(&a).await.unwrap();
    store.create_facet(&b).await.unwrap();

    let edge = make_edge(a.id, b.id, EdgeKind::RelatesTo);
    store.add_edge(&edge).await.unwrap();

    store
        .remove_edge(a.id, b.id, &EdgeKind::RelatesTo)
        .await
        .unwrap();

    let edges = store
        .get_edges(a.id, Direction::Outgoing, None)
        .await
        .unwrap();
    assert!(edges.is_empty());
}

// ── Edge kind parsing (mirrors hub.link validation) ────────────────

#[tokio::test]
async fn test_edge_kind_roundtrip() {
    let kinds = vec![
        ("depends_on", EdgeKind::DependsOn),
        ("blocks", EdgeKind::Blocks),
        ("relates_to", EdgeKind::RelatesTo),
        ("duplicates", EdgeKind::Duplicates),
    ];
    for (s, expected) in kinds {
        let parsed: EdgeKind = s.parse().unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(parsed.to_string(), s);
    }
}

#[tokio::test]
async fn test_invalid_edge_kind() {
    let result: Result<EdgeKind, String> = "not_a_kind".parse();
    assert!(result.is_err());
}

// ── Links direction query (mirrors hub.links) ──────────────────────

#[tokio::test]
async fn test_links_direction_filtering() {
    let (store, _dir) = temp_store().await;

    let a = make_facet("A", None, "user", "open");
    let b = make_facet("B", None, "user", "open");
    let c = make_facet("C", None, "user", "open");
    store.create_facet(&a).await.unwrap();
    store.create_facet(&b).await.unwrap();
    store.create_facet(&c).await.unwrap();

    store
        .add_edge(&make_edge(a.id, b.id, EdgeKind::DependsOn))
        .await
        .unwrap();
    store
        .add_edge(&make_edge(c.id, a.id, EdgeKind::Blocks))
        .await
        .unwrap();

    // Outgoing from A → only A→B
    let out = store
        .get_edges(a.id, Direction::Outgoing, None)
        .await
        .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to_id, b.id);

    // Incoming to A → only C→A
    let inc = store
        .get_edges(a.id, Direction::Incoming, None)
        .await
        .unwrap();
    assert_eq!(inc.len(), 1);
    assert_eq!(inc[0].from_id, c.id);

    // Both → 2 edges
    let both = store
        .get_edges(a.id, Direction::Both, None)
        .await
        .unwrap();
    assert_eq!(both.len(), 2);
}

// ── List children with child_count (mirrors hub.list summary) ──────

#[tokio::test]
async fn test_list_with_child_count() {
    let (store, _dir) = temp_store().await;

    let parent = make_facet("parent", None, "user", "open");
    store.create_facet(&parent).await.unwrap();

    for i in 0..3 {
        let child = make_facet(&format!("child-{i}"), Some(parent.id), "user", "open");
        store.create_facet(&child).await.unwrap();
    }

    // hub.list does: list_children, then count_children for each
    let children = store.list_children(Some(parent.id)).await.unwrap();
    assert_eq!(children.len(), 3);

    for child in &children {
        let count = store.count_children(Some(child.id)).await.unwrap();
        assert_eq!(count, 0, "leaf children should have 0 children");
    }
}

// ── Complex scenario: multi-level blocked detection ────────────────

#[tokio::test]
async fn test_blocked_scoped_to_parent() {
    let (store, _dir) = temp_store().await;

    let project = make_facet("project", None, "user", "open");
    store.create_facet(&project).await.unwrap();

    let task_a = make_facet("task A", Some(project.id), "user", "open");
    let task_b = make_facet("task B", Some(project.id), "user", "open");
    let task_c = make_facet("task C", Some(project.id), "user", "done");
    store.create_facet(&task_a).await.unwrap();
    store.create_facet(&task_b).await.unwrap();
    store.create_facet(&task_c).await.unwrap();

    // A depends on B (open) → A is blocked
    // A depends on C (done) → not a blocker
    store
        .add_edge(&make_edge(task_a.id, task_b.id, EdgeKind::DependsOn))
        .await
        .unwrap();
    store
        .add_edge(&make_edge(task_a.id, task_c.id, EdgeKind::DependsOn))
        .await
        .unwrap();

    // Replicate hub.blocked(parent_id = Some(project.id))
    let facets = store.list_children(Some(project.id)).await.unwrap();
    let mut blocked_list = Vec::new();

    for facet in &facets {
        let deps = store
            .get_edges(facet.id, Direction::Outgoing, Some(&EdgeKind::DependsOn))
            .await
            .unwrap();
        let mut blockers = Vec::new();
        for dep in &deps {
            if let Ok(target) = store.get_facet(dep.to_id).await {
                if target.status != "done" {
                    blockers.push(dep.to_id);
                }
            }
        }
        if !blockers.is_empty() {
            blocked_list.push((facet.id, blockers));
        }
    }

    // Only A should be blocked, only by B (C is done)
    assert_eq!(blocked_list.len(), 1);
    assert_eq!(blocked_list[0].0, task_a.id);
    assert_eq!(blocked_list[0].1, vec![task_b.id]);
}

// ── Facet with tenant metadata (mirrors hub.create with auth tenant) ──

#[tokio::test]
async fn test_facet_with_tenant_metadata() {
    let (store, _dir) = temp_store().await;

    let now = Utc::now();
    let mut meta = FacetMeta::default();
    meta.extra.insert(
        "tenant".into(),
        serde_json::Value::String("acme-corp".into()),
    );

    let facet = Facet {
        id: Uuid::new_v4(),
        parent_id: None,
        title: "tenant task".to_string(),
        body: None,
        status: "open".to_string(),
        owner: "tenantuser".to_string(),
        meta,
        created_at: now,
        updated_at: now,
    };

    store.create_facet(&facet).await.unwrap();
    let got = store.get_facet(facet.id).await.unwrap();

    let tenant = got.meta.extra.get("tenant").unwrap();
    assert_eq!(tenant.as_str(), Some("acme-corp"));
}
