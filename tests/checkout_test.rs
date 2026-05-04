//! Integration tests for checkout / diff / flush.

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use plexus_trak::checkout::{checkout, diff, flush, DiffEntry};
use plexus_trak::store::sqlite::SqliteStore;
use plexus_trak::store::FacetStore;
use plexus_trak::types::{Facet, FacetMeta};
use tempfile::TempDir;
use uuid::Uuid;

async fn temp_store() -> (Arc<SqliteStore>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("checkout_test.db");
    let store = SqliteStore::new(db_path.to_str().unwrap()).await.unwrap();
    (Arc::new(store), dir)
}

fn make_facet(title: &str, parent_id: Option<Uuid>, status: &str, body: Option<&str>) -> Facet {
    let now = Utc::now();
    Facet {
        id: Uuid::new_v4(),
        parent_id,
        title: title.to_string(),
        body: body.map(|b| b.to_string()),
        status: status.to_string(),
        owner: "tester".to_string(),
        meta: FacetMeta::default(),
        created_at: now,
        updated_at: now,
    }
}

fn read_file(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

// Each test gets its own checkout dir to avoid the "not empty" guard.
fn fresh_checkout_dir(td: &TempDir, name: &str) -> std::path::PathBuf {
    let p = td.path().join(name);
    // Make sure it doesn't exist yet (TempDir is empty by default but
    // tests sometimes nest under it).
    if p.exists() {
        std::fs::remove_dir_all(&p).unwrap();
    }
    p
}

// ─── Checkout tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_checkout_single_facet() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let f = make_facet("My Task", None, "open", Some("body line"));
    store.create_facet(&f).await.unwrap();

    let manifest = checkout(store.as_ref(), f.id, &work_dir).await.unwrap();
    assert_eq!(manifest.facets.len(), 1);
    let entry = manifest.facets.get(&f.id).unwrap();
    assert_eq!(entry.path, "my-task.md");

    let abs = work_dir.join("my-task.md");
    assert!(abs.exists(), "file should exist at {abs:?}");

    let contents = read_file(&abs);
    assert!(contents.contains(&format!("id: {}", f.id)));
    assert!(contents.contains("status: open"));
    assert!(contents.contains("# My Task"));
    assert!(contents.contains("body line"));

    // Manifest written to disk.
    let manifest_path = work_dir.join(".trak/manifest.json");
    assert!(manifest_path.exists(), "manifest should exist");
}

#[tokio::test]
async fn test_checkout_subtree() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let root = make_facet("TRAK-SRP: Identity", None, "open", None);
    let child = make_facet("SRP-1: First", Some(root.id), "open", None);
    let grandchild = make_facet("SRP-1-A: nested", Some(child.id), "open", None);

    store.create_facet(&root).await.unwrap();
    store.create_facet(&child).await.unwrap();
    store.create_facet(&grandchild).await.unwrap();

    let manifest = checkout(store.as_ref(), root.id, &work_dir).await.unwrap();
    assert_eq!(manifest.facets.len(), 3);

    // Layout:
    //   work/trak-srp.md
    //   work/trak-srp/srp-1.md
    //   work/trak-srp/srp-1/srp-1-a.md
    assert!(work_dir.join("trak-srp.md").exists());
    assert!(work_dir.join("trak-srp/srp-1.md").exists());
    assert!(work_dir.join("trak-srp/srp-1/srp-1-a.md").exists());
}

// ─── Diff tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_diff_no_changes() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let f = make_facet("Some Task", None, "open", Some("hello"));
    store.create_facet(&f).await.unwrap();
    checkout(store.as_ref(), f.id, &work_dir).await.unwrap();

    let diffs = diff(store.as_ref(), &work_dir).await.unwrap();
    assert!(diffs.is_empty(), "expected no diffs, got: {diffs:?}");
}

#[tokio::test]
async fn test_diff_modified_body() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let f = make_facet("Some Task", None, "open", Some("hello"));
    store.create_facet(&f).await.unwrap();
    checkout(store.as_ref(), f.id, &work_dir).await.unwrap();

    let abs = work_dir.join("some-task.md");
    let mut contents = read_file(&abs);
    contents = contents.replace("hello", "hello world updated");
    std::fs::write(&abs, contents).unwrap();

    let diffs = diff(store.as_ref(), &work_dir).await.unwrap();
    assert_eq!(diffs.len(), 1);
    assert!(matches!(diffs[0], DiffEntry::Modified { .. }));
}

#[tokio::test]
async fn test_diff_modified_title() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let f = make_facet("Old Title", None, "open", None);
    store.create_facet(&f).await.unwrap();
    checkout(store.as_ref(), f.id, &work_dir).await.unwrap();

    let abs = work_dir.join("old-title.md");
    let contents = read_file(&abs);
    let modified = contents.replace("# Old Title", "# Brand New Title");
    std::fs::write(&abs, modified).unwrap();

    let diffs = diff(store.as_ref(), &work_dir).await.unwrap();
    assert_eq!(diffs.len(), 1);
    match &diffs[0] {
        DiffEntry::Modified { parsed, .. } => assert_eq!(parsed.title, "Brand New Title"),
        d => panic!("expected Modified, got {d:?}"),
    }
}

#[tokio::test]
async fn test_diff_modified_status() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let f = make_facet("Task", None, "open", None);
    store.create_facet(&f).await.unwrap();
    checkout(store.as_ref(), f.id, &work_dir).await.unwrap();

    let abs = work_dir.join("task.md");
    let contents = read_file(&abs);
    let modified = contents.replace("status: open", "status: done");
    std::fs::write(&abs, modified).unwrap();

    let diffs = diff(store.as_ref(), &work_dir).await.unwrap();
    assert_eq!(diffs.len(), 1);
    match &diffs[0] {
        DiffEntry::Modified { parsed, .. } => assert_eq!(parsed.status, "done"),
        d => panic!("expected Modified, got {d:?}"),
    }
}

#[tokio::test]
async fn test_diff_new_file() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let f = make_facet("Existing", None, "open", None);
    store.create_facet(&f).await.unwrap();
    checkout(store.as_ref(), f.id, &work_dir).await.unwrap();

    // Add a new file with no id in frontmatter.
    let new_file = work_dir.join("brand-new.md");
    std::fs::write(
        &new_file,
        "---\nstatus: open\n---\n# Brand New\n\nfresh content\n",
    )
    .unwrap();

    let diffs = diff(store.as_ref(), &work_dir).await.unwrap();
    assert_eq!(diffs.len(), 1);
    match &diffs[0] {
        DiffEntry::Created { parsed, .. } => {
            assert_eq!(parsed.title, "Brand New");
            assert!(parsed.id.is_none());
        }
        d => panic!("expected Created, got {d:?}"),
    }
}

#[tokio::test]
async fn test_diff_deleted_file() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let parent = make_facet("Parent", None, "open", None);
    let child = make_facet("Child", Some(parent.id), "open", None);
    store.create_facet(&parent).await.unwrap();
    store.create_facet(&child).await.unwrap();

    checkout(store.as_ref(), parent.id, &work_dir).await.unwrap();

    // Delete the child file.
    let child_path = work_dir.join("parent/child.md");
    assert!(child_path.exists());
    std::fs::remove_file(&child_path).unwrap();

    let diffs = diff(store.as_ref(), &work_dir).await.unwrap();
    assert_eq!(diffs.len(), 1);
    match &diffs[0] {
        DiffEntry::Deleted { uuid, .. } => assert_eq!(*uuid, child.id),
        d => panic!("expected Deleted, got {d:?}"),
    }
}

#[tokio::test]
async fn test_diff_moved_file() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let root = make_facet("Root", None, "open", None);
    let parent_a = make_facet("Parent A", Some(root.id), "open", None);
    let parent_b = make_facet("Parent B", Some(root.id), "open", None);
    let child = make_facet("Child", Some(parent_a.id), "open", None);

    store.create_facet(&root).await.unwrap();
    store.create_facet(&parent_a).await.unwrap();
    store.create_facet(&parent_b).await.unwrap();
    store.create_facet(&child).await.unwrap();

    checkout(store.as_ref(), root.id, &work_dir).await.unwrap();

    // Layout under root/parent-a/child.md → move to root/parent-b/child.md
    let from = work_dir.join("root/parent-a/child.md");
    let to_dir = work_dir.join("root/parent-b");
    let to = to_dir.join("child.md");
    assert!(from.exists());
    std::fs::create_dir_all(&to_dir).unwrap();
    std::fs::rename(&from, &to).unwrap();

    let diffs = diff(store.as_ref(), &work_dir).await.unwrap();
    let moves: Vec<_> = diffs
        .iter()
        .filter(|d| matches!(d, DiffEntry::Moved { .. }))
        .collect();
    assert_eq!(moves.len(), 1, "expected 1 move, got: {diffs:?}");
    if let DiffEntry::Moved { uuid, new_parent, .. } = moves[0] {
        assert_eq!(*uuid, child.id);
        assert_eq!(*new_parent, Some(parent_b.id));
    }
}

// ─── Flush tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_flush_creates_new_facet() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let f = make_facet("Existing", None, "open", None);
    store.create_facet(&f).await.unwrap();
    checkout(store.as_ref(), f.id, &work_dir).await.unwrap();

    // Add new file.
    let new_file = work_dir.join("new-task.md");
    std::fs::write(
        &new_file,
        "---\nstatus: open\n---\n# New Task\n\nthe body\n",
    )
    .unwrap();

    let report = flush(store.as_ref(), &work_dir, "owner1", false)
        .await
        .unwrap();
    assert_eq!(report.created, 1);

    // Verify it landed in the store.
    let roots = store.list_roots().await.unwrap();
    let created = roots.iter().find(|r| r.title == "New Task").unwrap();
    assert_eq!(created.status, "open");
    assert_eq!(created.owner, "owner1");
}

#[tokio::test]
async fn test_flush_updates_modified_facet() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let f = make_facet("Task", None, "open", Some("old body"));
    store.create_facet(&f).await.unwrap();
    checkout(store.as_ref(), f.id, &work_dir).await.unwrap();

    let abs = work_dir.join("task.md");
    let contents = read_file(&abs).replace("old body", "new updated body");
    std::fs::write(&abs, contents).unwrap();

    let report = flush(store.as_ref(), &work_dir, "owner1", false)
        .await
        .unwrap();
    assert_eq!(report.modified, 1);

    let updated = store.get_facet(f.id).await.unwrap();
    assert!(updated.body.unwrap().contains("new updated body"));
}

#[tokio::test]
async fn test_flush_deletes_missing_file() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let parent = make_facet("Parent", None, "open", None);
    let child = make_facet("Child", Some(parent.id), "open", None);
    store.create_facet(&parent).await.unwrap();
    store.create_facet(&child).await.unwrap();

    checkout(store.as_ref(), parent.id, &work_dir).await.unwrap();

    let child_path = work_dir.join("parent/child.md");
    std::fs::remove_file(&child_path).unwrap();

    let report = flush(store.as_ref(), &work_dir, "owner1", false)
        .await
        .unwrap();
    assert_eq!(report.deleted, 1);

    assert!(store.get_facet(child.id).await.is_err());
}

#[tokio::test]
async fn test_flush_handles_move() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let root = make_facet("Root", None, "open", None);
    let parent_a = make_facet("Parent A", Some(root.id), "open", None);
    let parent_b = make_facet("Parent B", Some(root.id), "open", None);
    let child = make_facet("Child", Some(parent_a.id), "open", None);

    store.create_facet(&root).await.unwrap();
    store.create_facet(&parent_a).await.unwrap();
    store.create_facet(&parent_b).await.unwrap();
    store.create_facet(&child).await.unwrap();

    checkout(store.as_ref(), root.id, &work_dir).await.unwrap();

    let from = work_dir.join("root/parent-a/child.md");
    let to_dir = work_dir.join("root/parent-b");
    std::fs::create_dir_all(&to_dir).unwrap();
    std::fs::rename(&from, to_dir.join("child.md")).unwrap();

    let report = flush(store.as_ref(), &work_dir, "owner1", false)
        .await
        .unwrap();
    assert_eq!(report.moved, 1);

    let updated = store.get_facet(child.id).await.unwrap();
    assert_eq!(updated.parent_id, Some(parent_b.id));
}

#[tokio::test]
async fn test_flush_conflict_detection() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let f = make_facet("Task", None, "open", Some("original"));
    store.create_facet(&f).await.unwrap();
    checkout(store.as_ref(), f.id, &work_dir).await.unwrap();

    // Sleep a hair to ensure new updated_at is distinct.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Modify in the store (simulating concurrent edit).
    let mut server_copy = store.get_facet(f.id).await.unwrap();
    server_copy.body = Some("server-side change".into());
    server_copy.updated_at = Utc::now();
    store.update_facet(&server_copy).await.unwrap();

    // Modify on disk.
    let abs = work_dir.join("task.md");
    let contents = read_file(&abs).replace("original", "local-side change");
    std::fs::write(&abs, contents).unwrap();

    let report = flush(store.as_ref(), &work_dir, "owner1", false)
        .await
        .unwrap();
    assert_eq!(report.conflicts.len(), 1, "expected 1 conflict");
    assert_eq!(report.modified, 0, "modify should have been skipped");

    // Server still has its version.
    let after = store.get_facet(f.id).await.unwrap();
    assert_eq!(after.body.unwrap(), "server-side change");
}

#[tokio::test]
async fn test_flush_conflict_force() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let f = make_facet("Task", None, "open", Some("original"));
    store.create_facet(&f).await.unwrap();
    checkout(store.as_ref(), f.id, &work_dir).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let mut server_copy = store.get_facet(f.id).await.unwrap();
    server_copy.body = Some("server-side change".into());
    server_copy.updated_at = Utc::now();
    store.update_facet(&server_copy).await.unwrap();

    let abs = work_dir.join("task.md");
    let contents = read_file(&abs).replace("original", "local-side change");
    std::fs::write(&abs, contents).unwrap();

    let report = flush(store.as_ref(), &work_dir, "owner1", true)
        .await
        .unwrap();
    assert!(report.conflicts.is_empty());
    assert_eq!(report.modified, 1);

    let after = store.get_facet(f.id).await.unwrap();
    assert!(after.body.unwrap().contains("local-side change"));
}

#[tokio::test]
async fn test_roundtrip_no_drift() {
    let (store, _db_dir) = temp_store().await;
    let work = TempDir::new().unwrap();
    let work_dir = fresh_checkout_dir(&work, "co");

    let root = make_facet("Root", None, "open", Some("root body"));
    let child = make_facet("Child", Some(root.id), "open", Some("child body"));
    store.create_facet(&root).await.unwrap();
    store.create_facet(&child).await.unwrap();

    checkout(store.as_ref(), root.id, &work_dir).await.unwrap();

    let report = flush(store.as_ref(), &work_dir, "owner1", false)
        .await
        .unwrap();
    assert_eq!(report.created, 0);
    assert_eq!(report.modified, 0);
    assert_eq!(report.deleted, 0);
    assert_eq!(report.moved, 0);
    assert!(report.conflicts.is_empty());
}
