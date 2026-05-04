//! Integration tests for DiscussStore — comments on facets.
//!
//! Tests operate on the store directly, since the hub methods are RPC-only.
//! Authorization (only-author-can-edit/delete) lives in the hub layer and is
//! exercised separately at the integration level.

use chrono::Utc;
use plexus_trak::store::discuss::{Comment, DiscussStore};
use plexus_trak::store::sqlite::SqliteStore;
use tempfile::TempDir;
use uuid::Uuid;

async fn make_store() -> (DiscussStore, TempDir) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("test.db");
    let sqlite = SqliteStore::new(path.to_str().unwrap()).await.unwrap();
    let discuss = DiscussStore::new(sqlite.pool().clone());
    discuss.migrate().await.unwrap();
    (discuss, dir)
}

fn make_comment(facet_id: Uuid, author: &str, body: &str) -> Comment {
    let now = Utc::now();
    Comment {
        id: Uuid::new_v4(),
        facet_id,
        author: author.to_string(),
        author_name: Some(format!("Display {author}")),
        body: body.to_string(),
        created_at: now,
        updated_at: now,
        edited: false,
        parent_comment_id: None,
    }
}

#[tokio::test]
async fn test_create_and_get_comment() {
    let (store, _dir) = make_store().await;
    let facet = Uuid::new_v4();
    let c = make_comment(facet, "alice", "hello world");
    let id = c.id;

    store.create_comment(&c).await.unwrap();
    let got = store.get_comment(id).await.unwrap().expect("should exist");

    assert_eq!(got.id, id);
    assert_eq!(got.facet_id, facet);
    assert_eq!(got.author, "alice");
    assert_eq!(got.author_name.as_deref(), Some("Display alice"));
    assert_eq!(got.body, "hello world");
    assert!(!got.edited);
    assert!(got.parent_comment_id.is_none());
}

#[tokio::test]
async fn test_list_comments_empty() {
    let (store, _dir) = make_store().await;
    let facet = Uuid::new_v4();

    let list = store.list_comments(facet, 50, 0).await.unwrap();
    assert!(list.is_empty());

    let total = store.count_comments(facet).await.unwrap();
    assert_eq!(total, 0);
}

#[tokio::test]
async fn test_list_comments_ordered() {
    // List returns oldest-first (chronological thread order).
    let (store, _dir) = make_store().await;
    let facet = Uuid::new_v4();

    // Create with explicit, increasing timestamps so ordering is deterministic.
    let base = Utc::now();
    for i in 0..3 {
        let mut c = make_comment(facet, "alice", &format!("comment {i}"));
        c.created_at = base + chrono::Duration::seconds(i);
        c.updated_at = c.created_at;
        store.create_comment(&c).await.unwrap();
    }

    let list = store.list_comments(facet, 50, 0).await.unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].body, "comment 0");
    assert_eq!(list[1].body, "comment 1");
    assert_eq!(list[2].body, "comment 2");
}

#[tokio::test]
async fn test_list_comments_pagination() {
    let (store, _dir) = make_store().await;
    let facet = Uuid::new_v4();

    let base = Utc::now();
    for i in 0..10 {
        let mut c = make_comment(facet, "alice", &format!("c{i}"));
        c.created_at = base + chrono::Duration::seconds(i);
        c.updated_at = c.created_at;
        store.create_comment(&c).await.unwrap();
    }

    // Page: limit=3, offset=3 → c3, c4, c5
    let page = store.list_comments(facet, 3, 3).await.unwrap();
    assert_eq!(page.len(), 3);
    assert_eq!(page[0].body, "c3");
    assert_eq!(page[1].body, "c4");
    assert_eq!(page[2].body, "c5");

    // Last page: limit=3, offset=9 → just c9
    let last = store.list_comments(facet, 3, 9).await.unwrap();
    assert_eq!(last.len(), 1);
    assert_eq!(last[0].body, "c9");

    // Past end: limit=3, offset=20 → empty
    let past = store.list_comments(facet, 3, 20).await.unwrap();
    assert!(past.is_empty());
}

#[tokio::test]
async fn test_count_comments() {
    let (store, _dir) = make_store().await;
    let facet = Uuid::new_v4();

    for i in 0..5 {
        let c = make_comment(facet, "alice", &format!("c{i}"));
        store.create_comment(&c).await.unwrap();
    }

    let total = store.count_comments(facet).await.unwrap();
    assert_eq!(total, 5);
}

#[tokio::test]
async fn test_update_comment() {
    let (store, _dir) = make_store().await;
    let facet = Uuid::new_v4();
    let mut c = make_comment(facet, "alice", "original body");
    // Anchor created_at in the past so updated_at is observably later.
    c.created_at = Utc::now() - chrono::Duration::seconds(5);
    c.updated_at = c.created_at;
    let id = c.id;
    let original_updated = c.updated_at;

    store.create_comment(&c).await.unwrap();
    store.update_comment(id, "edited body").await.unwrap();

    let got = store.get_comment(id).await.unwrap().unwrap();
    assert_eq!(got.body, "edited body");
    assert!(got.edited, "edited flag should be set");
    assert!(
        got.updated_at > original_updated,
        "updated_at should advance"
    );
    assert_eq!(got.created_at, c.created_at, "created_at preserved");
}

#[tokio::test]
async fn test_delete_comment() {
    let (store, _dir) = make_store().await;
    let facet = Uuid::new_v4();
    let c = make_comment(facet, "alice", "doomed");
    let id = c.id;

    store.create_comment(&c).await.unwrap();
    let existed = store.delete_comment(id).await.unwrap();
    assert!(existed);

    let got = store.get_comment(id).await.unwrap();
    assert!(got.is_none());
}

#[tokio::test]
async fn test_delete_nonexistent_returns_false() {
    let (store, _dir) = make_store().await;
    let unknown = Uuid::new_v4();
    let existed = store.delete_comment(unknown).await.unwrap();
    assert!(!existed);
}

#[tokio::test]
async fn test_comments_isolated_per_facet() {
    let (store, _dir) = make_store().await;
    let facet_a = Uuid::new_v4();
    let facet_b = Uuid::new_v4();

    for i in 0..3 {
        let c = make_comment(facet_a, "alice", &format!("a{i}"));
        store.create_comment(&c).await.unwrap();
    }
    for i in 0..2 {
        let c = make_comment(facet_b, "bob", &format!("b{i}"));
        store.create_comment(&c).await.unwrap();
    }

    let on_a = store.list_comments(facet_a, 50, 0).await.unwrap();
    let on_b = store.list_comments(facet_b, 50, 0).await.unwrap();

    assert_eq!(on_a.len(), 3);
    assert_eq!(on_b.len(), 2);
    assert!(on_a.iter().all(|c| c.facet_id == facet_a));
    assert!(on_b.iter().all(|c| c.facet_id == facet_b));
    assert_eq!(store.count_comments(facet_a).await.unwrap(), 3);
    assert_eq!(store.count_comments(facet_b).await.unwrap(), 2);
}

#[tokio::test]
async fn test_threaded_reply() {
    let (store, _dir) = make_store().await;
    let facet = Uuid::new_v4();

    let mut parent = make_comment(facet, "alice", "what do you all think?");
    parent.created_at = Utc::now() - chrono::Duration::seconds(10);
    parent.updated_at = parent.created_at;
    let parent_id = parent.id;
    store.create_comment(&parent).await.unwrap();

    let mut reply = make_comment(facet, "bob", "I think yes");
    reply.parent_comment_id = Some(parent_id);
    store.create_comment(&reply).await.unwrap();

    let list = store.list_comments(facet, 50, 0).await.unwrap();
    assert_eq!(list.len(), 2);

    // Both visible; reply links back to parent.
    let reply_loaded = list.iter().find(|c| c.id == reply.id).unwrap();
    assert_eq!(reply_loaded.parent_comment_id, Some(parent_id));

    let parent_loaded = list.iter().find(|c| c.id == parent_id).unwrap();
    assert!(parent_loaded.parent_comment_id.is_none());
}
