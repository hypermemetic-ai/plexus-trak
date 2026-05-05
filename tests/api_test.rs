//! Tests for TRAK-API-2 and TRAK-API-3.
//!
//! API-2: NewFacet / FacetUpdate types — title required, defaults applied,
//! tags / priority / meta_extra carried through, update merge semantics
//! (replace tags, shallow-merge meta_extra with null-deletes-key).
//!
//! API-3: filter_facets helper used by facet.list / search / grep — OR/AND
//! tag filters, priority OR filter, combinations, and the "empty = no filter"
//! invariant that keeps default behavior byte-for-byte unchanged.
//!
//! These tests exercise the typed helpers directly. The activation methods
//! delegate all business logic to NewFacet::into_facet, FacetUpdate::apply,
//! and filter_facets, so testing those covers the API contract end-to-end.

use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use plexus_trak::hubs::facet::filter_facets;
use plexus_trak::store::sqlite::SqliteStore;
use plexus_trak::store::FacetStore;
use plexus_trak::types::{Facet, FacetMeta, FacetUpdate, NewFacet};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

async fn temp_store() -> (Arc<SqliteStore>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("api_test.db");
    let store = SqliteStore::new(db_path.to_str().unwrap()).await.unwrap();
    (Arc::new(store), dir)
}

fn make_facet_with_meta(title: &str, meta: FacetMeta) -> Facet {
    let now = Utc::now();
    Facet {
        id: Uuid::new_v4(),
        parent_id: None,
        title: title.to_string(),
        body: None,
        status: "open".to_string(),
        owner: "tester".to_string(),
        meta,
        created_at: now,
        updated_at: now,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// TRAK-API-2 — NewFacet
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn newfacet_validates_empty_title() {
    let nf = NewFacet {
        title: "".into(),
        ..Default::default()
    };
    let err = nf.validate().unwrap_err();
    assert!(err.to_lowercase().contains("title"));
}

#[test]
fn newfacet_validates_whitespace_title() {
    let nf = NewFacet {
        title: "   ".into(),
        ..Default::default()
    };
    assert!(nf.validate().is_err());
}

#[test]
fn newfacet_into_facet_defaults() {
    let nf = NewFacet {
        title: "task".into(),
        ..Default::default()
    };
    nf.validate().unwrap();
    let f = nf.into_facet("alice".to_string(), None);
    assert_eq!(f.title, "task");
    assert_eq!(f.status, "open"); // default
    assert_eq!(f.owner, "alice");
    assert!(f.body.is_none());
    assert!(f.parent_id.is_none());
    assert!(f.meta.tags.is_none());
    assert!(f.meta.priority.is_none());
    assert!(f.meta.extra.is_empty());
}

#[test]
fn newfacet_carries_tags_priority_meta_extra() {
    let mut extra = serde_json::Map::new();
    extra.insert("sprint".into(), json!("24"));
    extra.insert("region".into(), json!("us"));

    let nf = NewFacet {
        title: "structured task".into(),
        body: Some("body text".into()),
        status: Some("in_progress".into()),
        tags: Some(vec!["repo:synapse".into(), "bug".into()]),
        priority: Some("high".into()),
        meta_extra: Some(extra),
        ..Default::default()
    };
    let f = nf.into_facet("ben".to_string(), None);
    assert_eq!(f.title, "structured task");
    assert_eq!(f.body.as_deref(), Some("body text"));
    assert_eq!(f.status, "in_progress");
    assert_eq!(
        f.meta.tags.as_deref(),
        Some(&["repo:synapse".to_string(), "bug".to_string()][..])
    );
    assert_eq!(f.meta.priority.as_deref(), Some("high"));
    assert_eq!(f.meta.extra.get("sprint").unwrap().as_str(), Some("24"));
    assert_eq!(f.meta.extra.get("region").unwrap().as_str(), Some("us"));
}

#[test]
fn newfacet_tenant_inserted_when_not_provided() {
    let nf = NewFacet {
        title: "t".into(),
        ..Default::default()
    };
    let f = nf.into_facet("alice".into(), Some("acme-corp".into()));
    assert_eq!(
        f.meta.extra.get("tenant").unwrap().as_str(),
        Some("acme-corp")
    );
}

#[test]
fn newfacet_explicit_tenant_in_meta_extra_wins() {
    // Caller-provided tenant in meta_extra takes precedence over auth tenant.
    let mut extra = serde_json::Map::new();
    extra.insert("tenant".into(), json!("override-tenant"));
    let nf = NewFacet {
        title: "t".into(),
        meta_extra: Some(extra),
        ..Default::default()
    };
    let f = nf.into_facet("alice".into(), Some("auth-tenant".into()));
    assert_eq!(
        f.meta.extra.get("tenant").unwrap().as_str(),
        Some("override-tenant")
    );
}

#[tokio::test]
async fn newfacet_roundtrip_through_store() {
    let (store, _dir) = temp_store().await;
    let nf = NewFacet {
        title: "roundtrip".into(),
        tags: Some(vec!["a".into(), "b".into()]),
        priority: Some("high".into()),
        ..Default::default()
    };
    let f = nf.into_facet("alice".into(), None);
    let id = f.id;
    store.create_facet(&f).await.unwrap();
    let got = store.get_facet(id).await.unwrap();
    assert_eq!(
        got.meta.tags.as_deref(),
        Some(&["a".to_string(), "b".to_string()][..])
    );
    assert_eq!(got.meta.priority.as_deref(), Some("high"));
}

// ─────────────────────────────────────────────────────────────────────────
// TRAK-API-2 — FacetUpdate
// ─────────────────────────────────────────────────────────────────────────

fn seeded_facet() -> Facet {
    let mut meta = FacetMeta::default();
    meta.tags = Some(vec!["alpha".into()]);
    meta.priority = Some("high".into());
    meta.extra
        .insert("sprint".into(), serde_json::Value::String("24".into()));
    meta.extra
        .insert("region".into(), serde_json::Value::String("us".into()));
    make_facet_with_meta("seeded", meta)
}

#[test]
fn update_replaces_tags() {
    let mut f = seeded_facet();
    let upd = FacetUpdate {
        tags: Some(vec!["beta".into()]),
        ..Default::default()
    };
    upd.apply(&mut f);
    assert_eq!(f.meta.tags.as_deref(), Some(&["beta".to_string()][..]));
}

#[test]
fn update_clears_tags_with_empty_vec() {
    let mut f = seeded_facet();
    let upd = FacetUpdate {
        tags: Some(vec![]),
        ..Default::default()
    };
    upd.apply(&mut f);
    assert_eq!(f.meta.tags.as_deref(), Some(&[][..]));
}

#[test]
fn update_omitted_tags_leaves_unchanged() {
    let mut f = seeded_facet();
    let upd = FacetUpdate::default(); // tags: None
    upd.apply(&mut f);
    assert_eq!(f.meta.tags.as_deref(), Some(&["alpha".to_string()][..]));
}

#[test]
fn update_omitted_priority_leaves_unchanged() {
    let mut f = seeded_facet();
    let upd = FacetUpdate::default();
    upd.apply(&mut f);
    assert_eq!(f.meta.priority.as_deref(), Some("high"));
}

#[test]
fn update_meta_extra_shallow_merges() {
    let mut f = seeded_facet();
    let mut extra = serde_json::Map::new();
    extra.insert("sprint".into(), json!("25")); // overwrite
    let upd = FacetUpdate {
        meta_extra: Some(extra),
        ..Default::default()
    };
    upd.apply(&mut f);
    // sprint replaced, region preserved
    assert_eq!(f.meta.extra.get("sprint").unwrap().as_str(), Some("25"));
    assert_eq!(f.meta.extra.get("region").unwrap().as_str(), Some("us"));
}

#[test]
fn update_meta_extra_null_deletes_key() {
    let mut f = seeded_facet();
    let mut extra = serde_json::Map::new();
    extra.insert("sprint".into(), serde_json::Value::Null);
    let upd = FacetUpdate {
        meta_extra: Some(extra),
        ..Default::default()
    };
    upd.apply(&mut f);
    assert!(f.meta.extra.get("sprint").is_none());
    // region untouched
    assert_eq!(f.meta.extra.get("region").unwrap().as_str(), Some("us"));
}

#[test]
fn update_combined_fields() {
    let mut f = seeded_facet();
    let upd = FacetUpdate {
        title: Some("renamed".into()),
        status: Some("done".into()),
        tags: Some(vec!["gamma".into()]),
        priority: Some("low".into()),
        ..Default::default()
    };
    upd.apply(&mut f);
    assert_eq!(f.title, "renamed");
    assert_eq!(f.status, "done");
    assert_eq!(f.meta.tags.as_deref(), Some(&["gamma".to_string()][..]));
    assert_eq!(f.meta.priority.as_deref(), Some("low"));
}

#[tokio::test]
async fn update_persists_through_store() {
    let (store, _dir) = temp_store().await;
    // Create a facet with tags=["a","b"], priority="high".
    let nf = NewFacet {
        title: "persist".into(),
        tags: Some(vec!["a".into(), "b".into()]),
        priority: Some("high".into()),
        ..Default::default()
    };
    let mut f = nf.into_facet("ben".into(), None);
    let id = f.id;
    store.create_facet(&f).await.unwrap();

    // Apply tags=["c"] — read back, observe meta.tags == ["c"].
    let upd = FacetUpdate {
        tags: Some(vec!["c".into()]),
        ..Default::default()
    };
    upd.apply(&mut f);
    store.update_facet(&f).await.unwrap();
    let got = store.get_facet(id).await.unwrap();
    assert_eq!(got.meta.tags.as_deref(), Some(&["c".to_string()][..]));
    // priority preserved (None in update == leave alone).
    assert_eq!(got.meta.priority.as_deref(), Some("high"));
}

// ─────────────────────────────────────────────────────────────────────────
// TRAK-API-3 — filter_facets
// ─────────────────────────────────────────────────────────────────────────

fn tagged(title: &str, tags: &[&str], priority: Option<&str>) -> Facet {
    let mut meta = FacetMeta::default();
    if !tags.is_empty() {
        meta.tags = Some(tags.iter().map(|s| s.to_string()).collect());
    }
    meta.priority = priority.map(|s| s.to_string());
    make_facet_with_meta(title, meta)
}

#[test]
fn filter_no_filters_keeps_all() {
    let facets = vec![
        tagged("a", &["x"], None),
        tagged("b", &[], Some("high")),
        tagged("c", &["y", "z"], Some("low")),
    ];
    let out = filter_facets(facets.clone(), None, None, None);
    assert_eq!(out.len(), 3);
    let out2 = filter_facets(facets, Some(&[]), Some(&[]), Some(&[]));
    assert_eq!(out2.len(), 3); // empty arrays == no filter
}

#[test]
fn filter_tags_or_semantics() {
    let facets = vec![
        tagged("a", &["x"], None),
        tagged("b", &["y"], None),
        tagged("c", &["z"], None),
        tagged("d", &[], None),
    ];
    let want = vec!["x".to_string(), "y".to_string()];
    let out = filter_facets(facets, Some(&want), None, None);
    let titles: Vec<&str> = out.iter().map(|f| f.title.as_str()).collect();
    assert_eq!(titles, vec!["a", "b"]);
}

#[test]
fn filter_tags_all_and_semantics() {
    let facets = vec![
        tagged("a", &["x", "y"], None),
        tagged("b", &["x"], None),       // missing y
        tagged("c", &["y", "z"], None),  // missing x
        tagged("d", &["x", "y", "z"], None),
    ];
    let want = vec!["x".to_string(), "y".to_string()];
    let out = filter_facets(facets, None, Some(&want), None);
    let titles: Vec<&str> = out.iter().map(|f| f.title.as_str()).collect();
    assert_eq!(titles, vec!["a", "d"]);
}

#[test]
fn filter_priority_or_semantics() {
    let facets = vec![
        tagged("a", &[], Some("high")),
        tagged("b", &[], Some("low")),
        tagged("c", &[], Some("critical")),
        tagged("d", &[], None), // no priority — must be excluded
    ];
    let want = vec!["high".to_string(), "critical".to_string()];
    let out = filter_facets(facets, None, None, Some(&want));
    let titles: Vec<&str> = out.iter().map(|f| f.title.as_str()).collect();
    assert_eq!(titles, vec!["a", "c"]);
}

#[test]
fn filter_combined_tags_and_priority() {
    let facets = vec![
        tagged("a", &["bug"], Some("high")),
        tagged("b", &["bug"], Some("low")),
        tagged("c", &["feature"], Some("high")),
        tagged("d", &["bug"], Some("critical")),
    ];
    let tag_want = vec!["bug".to_string()];
    let prio_want = vec!["high".to_string(), "critical".to_string()];
    let out = filter_facets(facets, Some(&tag_want), None, Some(&prio_want));
    let titles: Vec<&str> = out.iter().map(|f| f.title.as_str()).collect();
    assert_eq!(titles, vec!["a", "d"]);
}

#[test]
fn filter_excludes_facets_with_no_tags_when_tag_filter_given() {
    let facets = vec![
        tagged("has", &["x"], None),
        tagged("none", &[], None),
    ];
    let want = vec!["x".to_string()];
    let out = filter_facets(facets, Some(&want), None, None);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].title, "has");
}

#[test]
fn filter_tags_all_empty_facet_excluded() {
    let facets = vec![
        tagged("none", &[], None),
        tagged("has", &["x", "y"], None),
    ];
    let want = vec!["x".to_string()];
    let out = filter_facets(facets, None, Some(&want), None);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].title, "has");
}

#[tokio::test]
async fn filter_performance_1000_facets() {
    // Acceptance criterion 8: filtered list against 1000 facets under 100ms.
    let (store, _dir) = temp_store().await;
    let parent = make_facet_with_meta("parent", FacetMeta::default());
    store.create_facet(&parent).await.unwrap();

    for i in 0..1000 {
        let mut meta = FacetMeta::default();
        meta.tags = Some(vec![if i % 3 == 0 { "bug" } else { "feature" }.into()]);
        meta.priority = Some(if i % 2 == 0 { "high" } else { "low" }.into());
        let mut f = make_facet_with_meta(&format!("item-{i}"), meta);
        f.parent_id = Some(parent.id);
        store.create_facet(&f).await.unwrap();
    }

    let children = store.list_children(Some(parent.id)).await.unwrap();
    assert_eq!(children.len(), 1000);

    let tag_want = vec!["bug".to_string()];
    let prio_want = vec!["high".to_string()];
    let start = Instant::now();
    let filtered = filter_facets(children, Some(&tag_want), None, Some(&prio_want));
    let elapsed = start.elapsed();

    // Sanity: ~1/3 of 1000 are tagged "bug", and ~half of those are "high"
    // priority — so we expect roughly 1/6 of the seed (~167).
    assert!(filtered.len() > 100 && filtered.len() < 250);
    assert!(
        elapsed.as_millis() < 100,
        "filter took {}ms, expected <100ms",
        elapsed.as_millis()
    );
}
