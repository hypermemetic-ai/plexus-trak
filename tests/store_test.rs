use chrono::Utc;
use plexus_trak::store::sqlite::SqliteStore;
use plexus_trak::store::{Direction, FacetStore};
use plexus_trak::types::{Edge, EdgeKind, Facet, FacetMeta};
use tempfile::TempDir;
use uuid::Uuid;

/// Create a temporary SQLite store for testing.
async fn temp_store() -> (SqliteStore, TempDir) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let store = SqliteStore::new(db_path.to_str().unwrap()).await.unwrap();
    (store, dir)
}

/// Build a minimal facet with the given title and optional parent.
fn make_facet(title: &str, parent_id: Option<Uuid>) -> Facet {
    let now = Utc::now();
    Facet {
        id: Uuid::new_v4(),
        parent_id,
        title: title.to_string(),
        body: None,
        status: "open".to_string(),
        owner: "tester".to_string(),
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

// ── CRUD tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_and_get() {
    let (store, _dir) = temp_store().await;
    let facet = make_facet("deploy v5", None);
    let id = facet.id;

    store.create_facet(&facet).await.unwrap();
    let got = store.get_facet(id).await.unwrap();

    assert_eq!(got.id, id);
    assert_eq!(got.title, "deploy v5");
    assert_eq!(got.status, "open");
    assert_eq!(got.owner, "tester");
    assert!(got.parent_id.is_none());
}

#[tokio::test]
async fn test_get_nonexistent() {
    let (store, _dir) = temp_store().await;
    let result = store.get_facet(Uuid::new_v4()).await;
    assert!(result.is_err());
    // StoreError::NotFound
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not found"), "expected NotFound, got: {msg}");
}

#[tokio::test]
async fn test_update_facet() {
    let (store, _dir) = temp_store().await;
    let mut facet = make_facet("original", None);
    store.create_facet(&facet).await.unwrap();

    facet.title = "updated title".to_string();
    facet.status = "done".to_string();
    facet.updated_at = Utc::now();
    store.update_facet(&facet).await.unwrap();

    let got = store.get_facet(facet.id).await.unwrap();
    assert_eq!(got.title, "updated title");
    assert_eq!(got.status, "done");
}

#[tokio::test]
async fn test_delete_facet() {
    let (store, _dir) = temp_store().await;
    let facet = make_facet("to delete", None);
    let id = facet.id;
    store.create_facet(&facet).await.unwrap();

    store.delete_facet(id).await.unwrap();

    let result = store.get_facet(id).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_delete_nonexistent() {
    let (store, _dir) = temp_store().await;
    let result = store.delete_facet(Uuid::new_v4()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_delete_parent_orphans_children() {
    // FK is ON DELETE SET NULL, so children become roots
    let (store, _dir) = temp_store().await;
    let parent = make_facet("parent", None);
    let child1 = make_facet("child1", Some(parent.id));
    let child2 = make_facet("child2", Some(parent.id));

    store.create_facet(&parent).await.unwrap();
    store.create_facet(&child1).await.unwrap();
    store.create_facet(&child2).await.unwrap();

    store.delete_facet(parent.id).await.unwrap();

    // Children should still exist but with parent_id = None (orphaned to root)
    let c1 = store.get_facet(child1.id).await.unwrap();
    assert!(c1.parent_id.is_none(), "child should be orphaned to root");

    let c2 = store.get_facet(child2.id).await.unwrap();
    assert!(c2.parent_id.is_none());
}

// ── List / tree tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_list_roots() {
    let (store, _dir) = temp_store().await;
    for i in 0..3 {
        let f = make_facet(&format!("root-{i}"), None);
        store.create_facet(&f).await.unwrap();
    }

    let roots = store.list_roots().await.unwrap();
    assert_eq!(roots.len(), 3);
}

#[tokio::test]
async fn test_list_children() {
    let (store, _dir) = temp_store().await;
    let parent = make_facet("parent", None);
    store.create_facet(&parent).await.unwrap();

    for i in 0..3 {
        let child = make_facet(&format!("child-{i}"), Some(parent.id));
        store.create_facet(&child).await.unwrap();
    }

    let children = store.list_children(Some(parent.id)).await.unwrap();
    assert_eq!(children.len(), 3);
    for c in &children {
        assert_eq!(c.parent_id, Some(parent.id));
    }
}

#[tokio::test]
async fn test_list_children_empty() {
    let (store, _dir) = temp_store().await;
    let facet = make_facet("leaf", None);
    store.create_facet(&facet).await.unwrap();

    let children = store.list_children(Some(facet.id)).await.unwrap();
    assert!(children.is_empty());
}

#[tokio::test]
async fn test_parent_child_relationship() {
    let (store, _dir) = temp_store().await;
    let parent = make_facet("parent", None);
    let child = make_facet("child", Some(parent.id));

    store.create_facet(&parent).await.unwrap();
    store.create_facet(&child).await.unwrap();

    let ancestors = store.get_ancestors(child.id).await.unwrap();
    assert_eq!(ancestors.len(), 1);
    assert_eq!(ancestors[0].id, parent.id);
}

#[tokio::test]
async fn test_ancestors_chain() {
    let (store, _dir) = temp_store().await;
    let root = make_facet("root", None);
    let mid = make_facet("mid", Some(root.id));
    let leaf = make_facet("leaf", Some(mid.id));

    store.create_facet(&root).await.unwrap();
    store.create_facet(&mid).await.unwrap();
    store.create_facet(&leaf).await.unwrap();

    let ancestors = store.get_ancestors(leaf.id).await.unwrap();
    assert_eq!(ancestors.len(), 2);
    let ids: Vec<Uuid> = ancestors.iter().map(|a| a.id).collect();
    assert!(ids.contains(&root.id));
    assert!(ids.contains(&mid.id));
}

#[tokio::test]
async fn test_move_facet() {
    let (store, _dir) = temp_store().await;
    let a = make_facet("A", None);
    let b = make_facet("B", Some(a.id));
    let c = make_facet("C", Some(a.id));

    store.create_facet(&a).await.unwrap();
    store.create_facet(&b).await.unwrap();
    store.create_facet(&c).await.unwrap();

    // Move C from A to B
    store.move_facet(c.id, Some(b.id)).await.unwrap();

    let children_a = store.list_children(Some(a.id)).await.unwrap();
    let children_a_ids: Vec<Uuid> = children_a.iter().map(|f| f.id).collect();
    assert!(children_a_ids.contains(&b.id));
    assert!(!children_a_ids.contains(&c.id));

    let children_b = store.list_children(Some(b.id)).await.unwrap();
    assert_eq!(children_b.len(), 1);
    assert_eq!(children_b[0].id, c.id);
}

#[tokio::test]
async fn test_move_to_root() {
    let (store, _dir) = temp_store().await;
    let parent = make_facet("parent", None);
    let child = make_facet("child", Some(parent.id));

    store.create_facet(&parent).await.unwrap();
    store.create_facet(&child).await.unwrap();

    store.move_facet(child.id, None).await.unwrap();

    let roots = store.list_roots().await.unwrap();
    let root_ids: Vec<Uuid> = roots.iter().map(|f| f.id).collect();
    assert!(root_ids.contains(&child.id));

    let got = store.get_facet(child.id).await.unwrap();
    assert!(got.parent_id.is_none());
}

#[tokio::test]
async fn test_subtree() {
    let (store, _dir) = temp_store().await;
    let root = make_facet("root", None);
    let mid = make_facet("mid", Some(root.id));
    let leaf = make_facet("leaf", Some(mid.id));

    store.create_facet(&root).await.unwrap();
    store.create_facet(&mid).await.unwrap();
    store.create_facet(&leaf).await.unwrap();

    let tree = store.get_subtree(root.id).await.unwrap();
    assert_eq!(tree.len(), 3);

    // Depths should be 0, 1, 2
    let depths: Vec<u32> = tree.iter().map(|(_, d)| *d).collect();
    assert!(depths.contains(&0));
    assert!(depths.contains(&1));
    assert!(depths.contains(&2));

    // Root is at depth 0
    let (root_facet, root_depth) = tree.iter().find(|(f, _)| f.id == root.id).unwrap();
    assert_eq!(*root_depth, 0);
    assert_eq!(root_facet.title, "root");
}

#[tokio::test]
async fn test_count_children() {
    let (store, _dir) = temp_store().await;
    let parent = make_facet("parent", None);
    store.create_facet(&parent).await.unwrap();

    for i in 0..3 {
        let child = make_facet(&format!("child-{i}"), Some(parent.id));
        store.create_facet(&child).await.unwrap();
    }

    let count = store.count_children(Some(parent.id)).await.unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
async fn test_count_children_none_returns_roots() {
    let (store, _dir) = temp_store().await;
    for i in 0..4 {
        let f = make_facet(&format!("root-{i}"), None);
        store.create_facet(&f).await.unwrap();
    }

    let count = store.count_children(None).await.unwrap();
    assert_eq!(count, 4);
}

// ── Edge tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_add_edge() {
    let (store, _dir) = temp_store().await;
    let a = make_facet("A", None);
    let b = make_facet("B", None);
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

#[tokio::test]
async fn test_get_edges_incoming() {
    let (store, _dir) = temp_store().await;
    let a = make_facet("A", None);
    let b = make_facet("B", None);
    store.create_facet(&a).await.unwrap();
    store.create_facet(&b).await.unwrap();

    let edge = make_edge(a.id, b.id, EdgeKind::Blocks);
    store.add_edge(&edge).await.unwrap();

    let edges = store
        .get_edges(b.id, Direction::Incoming, None)
        .await
        .unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].from_id, a.id);
}

#[tokio::test]
async fn test_get_edges_both() {
    let (store, _dir) = temp_store().await;
    let a = make_facet("A", None);
    let b = make_facet("B", None);
    let c = make_facet("C", None);
    store.create_facet(&a).await.unwrap();
    store.create_facet(&b).await.unwrap();
    store.create_facet(&c).await.unwrap();

    let e1 = make_edge(a.id, b.id, EdgeKind::DependsOn);
    let e2 = make_edge(c.id, a.id, EdgeKind::RelatesTo);
    store.add_edge(&e1).await.unwrap();
    store.add_edge(&e2).await.unwrap();

    let edges = store
        .get_edges(a.id, Direction::Both, None)
        .await
        .unwrap();
    assert_eq!(edges.len(), 2);
}

#[tokio::test]
async fn test_remove_edge() {
    let (store, _dir) = temp_store().await;
    let a = make_facet("A", None);
    let b = make_facet("B", None);
    store.create_facet(&a).await.unwrap();
    store.create_facet(&b).await.unwrap();

    let edge = make_edge(a.id, b.id, EdgeKind::DependsOn);
    store.add_edge(&edge).await.unwrap();

    store
        .remove_edge(a.id, b.id, &EdgeKind::DependsOn)
        .await
        .unwrap();

    let edges = store
        .get_edges(a.id, Direction::Outgoing, None)
        .await
        .unwrap();
    assert!(edges.is_empty());
}

#[tokio::test]
async fn test_remove_edge_by_kind() {
    let (store, _dir) = temp_store().await;
    let a = make_facet("A", None);
    let b = make_facet("B", None);
    store.create_facet(&a).await.unwrap();
    store.create_facet(&b).await.unwrap();

    let e1 = make_edge(a.id, b.id, EdgeKind::DependsOn);
    let e2 = make_edge(a.id, b.id, EdgeKind::RelatesTo);
    store.add_edge(&e1).await.unwrap();
    store.add_edge(&e2).await.unwrap();

    // Remove only DependsOn
    store
        .remove_edge(a.id, b.id, &EdgeKind::DependsOn)
        .await
        .unwrap();

    let edges = store
        .get_edges(a.id, Direction::Outgoing, None)
        .await
        .unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].kind, EdgeKind::RelatesTo);
}

#[tokio::test]
async fn test_get_edges_filtered_by_kind() {
    let (store, _dir) = temp_store().await;
    let a = make_facet("A", None);
    let b = make_facet("B", None);
    store.create_facet(&a).await.unwrap();
    store.create_facet(&b).await.unwrap();

    let e1 = make_edge(a.id, b.id, EdgeKind::DependsOn);
    let e2 = make_edge(a.id, b.id, EdgeKind::RelatesTo);
    store.add_edge(&e1).await.unwrap();
    store.add_edge(&e2).await.unwrap();

    let edges = store
        .get_edges(a.id, Direction::Outgoing, Some(&EdgeKind::DependsOn))
        .await
        .unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].kind, EdgeKind::DependsOn);
}

// ── Search tests ───────────────────────────────────────────────────

#[tokio::test]
async fn test_search() {
    let (store, _dir) = temp_store().await;
    let f1 = make_facet("deploy v5", None);
    let f2 = make_facet("deploy v6", None);
    let f3 = make_facet("fix bug", None);

    store.create_facet(&f1).await.unwrap();
    store.create_facet(&f2).await.unwrap();
    store.create_facet(&f3).await.unwrap();

    let results = store.search("deploy").await.unwrap();
    assert_eq!(results.len(), 2);

    let titles: Vec<&str> = results.iter().map(|(f, _)| f.title.as_str()).collect();
    assert!(titles.contains(&"deploy v5"));
    assert!(titles.contains(&"deploy v6"));

    // Scores should be positive (FTS5 rank is negated)
    for (_, score) in &results {
        assert!(*score > 0.0, "score should be positive, got {score}");
    }
}

#[tokio::test]
async fn test_search_body() {
    let (store, _dir) = temp_store().await;
    let mut facet = make_facet("boring title", None);
    facet.body = Some("deploy the infrastructure changes".to_string());
    store.create_facet(&facet).await.unwrap();

    let results = store.search("deploy").await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0.id, facet.id);
}

#[tokio::test]
async fn test_search_no_results() {
    let (store, _dir) = temp_store().await;
    let f = make_facet("hello world", None);
    store.create_facet(&f).await.unwrap();

    let results = store.search("nonexistent").await.unwrap();
    assert!(results.is_empty());
}

// ── Meta / body tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_facet_with_body_and_meta() {
    let (store, _dir) = temp_store().await;
    let now = Utc::now();
    let mut meta = FacetMeta::default();
    meta.priority = Some("high".to_string());
    meta.tags = Some(vec!["backend".to_string(), "urgent".to_string()]);

    let facet = Facet {
        id: Uuid::new_v4(),
        parent_id: None,
        title: "with meta".to_string(),
        body: Some("detailed description".to_string()),
        status: "in_progress".to_string(),
        owner: "alice".to_string(),
        meta,
        created_at: now,
        updated_at: now,
    };

    store.create_facet(&facet).await.unwrap();
    let got = store.get_facet(facet.id).await.unwrap();

    assert_eq!(got.body.as_deref(), Some("detailed description"));
    assert_eq!(got.meta.priority.as_deref(), Some("high"));
    let tags = got.meta.tags.unwrap();
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&"backend".to_string()));
    assert!(tags.contains(&"urgent".to_string()));
}

#[tokio::test]
async fn test_update_nonexistent_facet() {
    let (store, _dir) = temp_store().await;
    let facet = make_facet("ghost", None);
    // Don't create it, just try to update
    let result = store.update_facet(&facet).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_move_nonexistent_facet() {
    let (store, _dir) = temp_store().await;
    let result = store.move_facet(Uuid::new_v4(), None).await;
    assert!(result.is_err());
}
