//! Pentest suite for the trak-local `TenantGate`.
//!
//! Each test mounts an attack the gate must defeat. The test names follow
//! the spec's nine cases (AUTHZ-TENANT-GATE-trak-facets). When a case
//! deviates from the spec, the per-test doc comment explains why.
//!
//! These tests exercise the gate directly. They do NOT go through the
//! activation/RPC layer because that layer's macro-generated dispatch
//! requires a full plexus-core dispatch fixture (out of scope), and the
//! per-handler refactor in `src/hubs/facet.rs` is a straight pass-through
//! to the gate — covering the gate covers the handler's tenant-isolation
//! behavior.

use std::sync::Arc;

use chrono::Utc;
use plexus_core::plexus::AuthContext;
use plexus_trak::store::sqlite::SqliteStore;
use plexus_trak::store::FacetStore;
use plexus_trak::tenant_gate::{GateError, TenantGate};
use plexus_trak::types::{Facet, FacetMeta};
use serde_json::{json, Value};
use tempfile::TempDir;
use uuid::Uuid;

// ─── Fixtures ────────────────────────────────────────────────────────────

async fn temp_store() -> (Arc<SqliteStore>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("tenant_iso.db");
    let store = SqliteStore::new(db_path.to_str().unwrap()).await.unwrap();
    (Arc::new(store), dir)
}

fn ctx_for(user: &str, tenant: &str) -> AuthContext {
    AuthContext::new(
        user.to_string(),
        format!("sess-{user}"),
        vec![],
        json!({"tenant_id": tenant}),
    )
}

/// Build a facet with no tenant tag — used to construct facets we then
/// hand to `gate.create` so the gate stamps the tenant.
fn untagged_facet(title: &str, parent: Option<Uuid>) -> Facet {
    let now = Utc::now();
    Facet {
        id: Uuid::new_v4(),
        parent_id: parent,
        title: title.to_string(),
        body: None,
        status: "open".to_string(),
        owner: "anyone".to_string(),
        meta: FacetMeta::default(),
        created_at: now,
        updated_at: now,
    }
}

/// Build a facet pre-tagged with a tenant string. Used by tests that need
/// to seed the store with a tenant-owned facet WITHOUT going through the
/// gate's create (e.g. to set up an attacker scenario).
fn tagged_facet(title: &str, tenant: &str) -> Facet {
    let mut f = untagged_facet(title, None);
    f.meta
        .extra
        .insert("tenant".to_string(), Value::String(tenant.to_string()));
    f
}

/// Read the tenant tag off a stored facet — verification helper.
fn read_tenant(facet: &Facet) -> Option<&str> {
    facet.meta.extra.get("tenant").and_then(|v| v.as_str())
}

// ─── Pentest 1: cross-tenant read returns NotFound ───────────────────────

#[tokio::test]
async fn cross_tenant_read_returns_not_found() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let bob_ctx = ctx_for("bob", "tenant-B");

    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;
    let bob_gate = TenantGate::from_auth(store.clone(), Some(&bob_ctx)).await;

    let created = alice_gate
        .create(untagged_facet("alice's secret", None))
        .await
        .expect("alice creates");
    assert_eq!(read_tenant(&created), Some("tenant-A"));

    // Bob probes alice's facet by UUID. He must get NotFound, NOT Forbidden.
    // Returning Forbidden would leak existence (oracle attack).
    let err = bob_gate.get(created.id).await.unwrap_err();
    assert!(
        matches!(err, GateError::NotFound),
        "expected NotFound (existence-oracle defense), got {err:?}"
    );

    // Alice can still see it.
    let seen = alice_gate.get(created.id).await.unwrap();
    assert_eq!(seen.id, created.id);
}

// ─── Pentest 2: cross-tenant update returns Forbidden ────────────────────

#[tokio::test]
async fn cross_tenant_update_returns_forbidden() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let bob_ctx = ctx_for("bob", "tenant-B");

    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;
    let bob_gate = TenantGate::from_auth(store.clone(), Some(&bob_ctx)).await;

    let alice_facet = alice_gate
        .create(untagged_facet("alice's task", None))
        .await
        .unwrap();

    // Bob tries to update Alice's facet. He can guess the UUID (e.g. from a
    // log leak); the gate must refuse with Forbidden because the facet
    // EXISTS but is foreign-tenant. (Contrast pentest 1: read uses NotFound
    // to hide existence; writes already concede existence via the
    // create-paired delete path, so Forbidden is the honest signal.)
    let mut mutated = alice_facet.clone();
    mutated.title = "BOB OWNS THIS NOW".to_string();

    let err = bob_gate.update(mutated).await.unwrap_err();
    assert!(
        matches!(err, GateError::Forbidden),
        "expected Forbidden for cross-tenant update, got {err:?}"
    );

    // Verify the underlying facet is unchanged.
    let reread = alice_gate.get(alice_facet.id).await.unwrap();
    assert_eq!(reread.title, "alice's task");
}

// ─── Pentest 3: cross-tenant delete returns Forbidden ────────────────────

#[tokio::test]
async fn cross_tenant_delete_returns_forbidden() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let bob_ctx = ctx_for("bob", "tenant-B");

    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;
    let bob_gate = TenantGate::from_auth(store.clone(), Some(&bob_ctx)).await;

    let alice_facet = alice_gate
        .create(untagged_facet("alice's", None))
        .await
        .unwrap();

    let err = bob_gate.delete(alice_facet.id).await.unwrap_err();
    assert!(
        matches!(err, GateError::Forbidden),
        "expected Forbidden for cross-tenant delete, got {err:?}"
    );

    // Verify the facet still exists.
    let _ = alice_gate.get(alice_facet.id).await.unwrap();
}

// ─── Pentest 4: cross-tenant list excludes other tenant's facets ─────────

#[tokio::test]
async fn cross_tenant_list_excludes_other_tenant_facets() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let bob_ctx = ctx_for("bob", "tenant-B");

    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;
    let bob_gate = TenantGate::from_auth(store.clone(), Some(&bob_ctx)).await;

    // Both tenants have facets at the root level.
    let a1 = alice_gate
        .create(untagged_facet("a1", None))
        .await
        .unwrap();
    let a2 = alice_gate
        .create(untagged_facet("a2", None))
        .await
        .unwrap();
    let b1 = bob_gate.create(untagged_facet("b1", None)).await.unwrap();

    // Alice lists roots — sees only her own.
    let a_list = alice_gate.list_children(None).await.unwrap();
    let a_ids: std::collections::HashSet<Uuid> = a_list.iter().map(|f| f.id).collect();
    assert!(a_ids.contains(&a1.id));
    assert!(a_ids.contains(&a2.id));
    assert!(
        !a_ids.contains(&b1.id),
        "tenant-A listed tenant-B's facet (leak)"
    );

    // Bob lists roots — sees only his own.
    let b_list = bob_gate.list_children(None).await.unwrap();
    let b_ids: std::collections::HashSet<Uuid> = b_list.iter().map(|f| f.id).collect();
    assert!(b_ids.contains(&b1.id));
    assert!(!b_ids.contains(&a1.id));
    assert!(!b_ids.contains(&a2.id));
}

// ─── Pentest 5: anonymous cannot write ───────────────────────────────────

#[tokio::test]
async fn anonymous_cannot_write() {
    let (store, _dir) = temp_store().await;

    // Anonymous gate: no AuthContext.
    let anon_gate = TenantGate::from_auth(store.clone(), None).await;

    // create
    let err = anon_gate
        .create(untagged_facet("attack", None))
        .await
        .unwrap_err();
    assert!(
        matches!(err, GateError::Unauthenticated),
        "anonymous create must be Unauthenticated, got {err:?}"
    );

    // Seed a real facet via an authed gate so update/delete have a target.
    let alice = ctx_for("alice", "tenant-A");
    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice)).await;
    let target = alice_gate
        .create(untagged_facet("victim", None))
        .await
        .unwrap();

    // update
    let mut mutated = target.clone();
    mutated.title = "pwnd".into();
    let err = anon_gate.update(mutated).await.unwrap_err();
    assert!(
        matches!(err, GateError::Forbidden),
        "anonymous update must be denied, got {err:?}"
    );
    // FINDING: anon writes surface as Forbidden (not Unauthenticated)
    // because the gate's can_write() returns false for caller=None across
    // the board. The control-flow is "auth check happens inside can_write".
    // Functionally identical from the attacker's POV: the operation fails.
    // We could surface Unauthenticated specifically by early-returning in
    // update/delete when self.tenant.is_none(); leaving as Forbidden is
    // consistent with how can_write encodes "no caller → no writes".

    // delete
    let err = anon_gate.delete(target.id).await.unwrap_err();
    assert!(
        matches!(err, GateError::Forbidden),
        "anonymous delete must be denied, got {err:?}"
    );
}

// ─── Pentest 6: anonymous reads only public facets ───────────────────────

#[tokio::test]
async fn anonymous_reads_only_public_facets() {
    let (store, _dir) = temp_store().await;

    let alice = ctx_for("alice", "tenant-A");
    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice)).await;
    let anon_gate = TenantGate::from_auth(store.clone(), None).await;

    // Alice (tenant-A) creates a private facet.
    let private = alice_gate
        .create(untagged_facet("private", None))
        .await
        .unwrap();

    // Anonymous user cannot get it.
    let err = anon_gate.get(private.id).await.unwrap_err();
    assert!(matches!(err, GateError::NotFound));

    // Anonymous user list at root is empty (alice's facet is filtered out).
    let listed = anon_gate.list_children(None).await.unwrap();
    assert!(listed.is_empty(), "anon listed tenant-A's facet");

    // Seed a public (no-tenant) facet directly through the store.
    // The gate never creates a public facet — caller's tenant always wins
    // on create — so we go around the gate for the public fixture.
    let public_facet = untagged_facet("public-doc", None);
    let public_id = public_facet.id;
    store.create_facet(&public_facet).await.unwrap();

    // Anonymous user can read it.
    let seen = anon_gate.get(public_id).await.unwrap();
    assert_eq!(seen.id, public_id);

    // And it appears in their list.
    let listed = anon_gate.list_children(None).await.unwrap();
    assert!(
        listed.iter().any(|f| f.id == public_id),
        "anon's list missing the public facet"
    );

    // Alice can also see the public facet (tenant sees public + own).
    let listed_a = alice_gate.list_children(None).await.unwrap();
    assert!(
        listed_a.iter().any(|f| f.id == public_id),
        "alice's list missing the public facet"
    );
}

// ─── Pentest 7: tenant cannot hop via update ─────────────────────────────

#[tokio::test]
async fn tenant_cannot_hop_via_update() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;

    let original = alice_gate
        .create(untagged_facet("alice's facet", None))
        .await
        .unwrap();
    assert_eq!(read_tenant(&original), Some("tenant-A"));

    // Alice tries to move the facet to tenant-B by overwriting meta.extra.
    let mut hop_attempt = original.clone();
    hop_attempt.meta.extra.insert(
        "tenant".to_string(),
        Value::String("tenant-B".to_string()),
    );
    // Also try setting some other innocuous field to make sure the update
    // actually goes through and the tenant-preserve is the only thing
    // protecting us.
    hop_attempt.title = "renamed".to_string();

    let updated = alice_gate.update(hop_attempt).await.unwrap();
    assert_eq!(updated.title, "renamed", "title should have been updated");
    assert_eq!(
        read_tenant(&updated),
        Some("tenant-A"),
        "tenant must NOT hop via update"
    );

    // Re-fetch from store to be certain it's persisted, not just the
    // returned-value-was-fixed-locally illusion.
    let reread = alice_gate.get(updated.id).await.unwrap();
    assert_eq!(read_tenant(&reread), Some("tenant-A"));
    assert_eq!(reread.title, "renamed");
}

// ─── Pentest 8: tenant cannot hop via create metadata override ───────────

#[tokio::test]
async fn tenant_cannot_hop_via_create_metadata_override() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;

    // Alice forges a "tenant" key in meta_extra, hoping the gate honors
    // her supplied value over her resolved tenant.
    let mut forged = untagged_facet("a", None);
    forged.meta.extra.insert(
        "tenant".to_string(),
        Value::String("tenant-B".to_string()),
    );

    let created = alice_gate.create(forged).await.unwrap();

    // The gate must overwrite the caller's forged value with the resolved
    // tenant — caller's tenant wins.
    assert_eq!(
        read_tenant(&created),
        Some("tenant-A"),
        "create must overwrite forged meta.extra.tenant with caller's resolved tenant"
    );

    // And the persisted record agrees.
    let reread = alice_gate.get(created.id).await.unwrap();
    assert_eq!(read_tenant(&reread), Some("tenant-A"));
}

// ─── Pentest 9: forged AuthContext does not grant tenant ─────────────────

#[tokio::test]
async fn forged_authcontext_does_not_grant_tenant() {
    let (store, _dir) = temp_store().await;

    // Seed a tenant-A facet so we have something cross-tenant to attack.
    {
        let real_alice = ctx_for("alice", "tenant-A");
        let real_gate = TenantGate::from_auth(store.clone(), Some(&real_alice)).await;
        real_gate
            .create(untagged_facet("alice's secret", None))
            .await
            .unwrap();
    }

    // Attacker fabricates an AuthContext: claims tenant_id = tenant-A but
    // session_id is empty (didn't go through a session validator). This
    // is the shape "JWT extracted but signature not verified" attacks
    // produce.
    //
    // The SealedTenant resolver (ClaimTenantResolver) does NOT itself check
    // is_authenticated() — it trusts the AuthContext as post-validator.
    // The gate adds defense-in-depth: from_auth() rejects any
    // AuthContext with !is_authenticated, even if it carries a claim.
    let forged = AuthContext::new(
        "attacker".to_string(),
        String::new(), // empty session → !is_authenticated
        vec![],
        json!({"tenant_id": "tenant-A"}),
    );
    let forged_gate = TenantGate::from_auth(store.clone(), Some(&forged)).await;

    // The gate must treat this caller as anonymous (no resolved tenant).
    assert!(
        forged_gate.caller_tenant().is_none(),
        "gate must reject AuthContext that fails is_authenticated() even with a claim present"
    );

    // Therefore the forged caller cannot write.
    let err = forged_gate
        .create(untagged_facet("attack", None))
        .await
        .unwrap_err();
    assert!(matches!(err, GateError::Unauthenticated));

    // And cannot read tenant-A facets.
    let visible = forged_gate.list_children(None).await.unwrap();
    // Tagged tenant-A facets should not appear — the only visible items
    // would be untagged/public ones. The fixture above only created a
    // tenant-A facet, so this must be empty.
    assert!(
        visible.is_empty(),
        "forged context saw tenant-A facets via anonymous fallthrough"
    );
}

// ─── Bonus pentest: tenant-tagged seed via store bypass ──────────────────

/// Verify that even if a facet appears in storage with a foreign tenant tag
/// (e.g. via a direct DB write outside the gate), cross-tenant access is
/// still denied. This tests the gate's read predicate independently of the
/// gate's create-time enforcement.
#[tokio::test]
async fn store_bypass_seed_is_still_isolated() {
    let (store, _dir) = temp_store().await;

    // Direct-write a tenant-B facet through the store, bypassing the gate
    // entirely. Simulates: legacy data, a different writer, a backup
    // import, etc.
    let raw = tagged_facet("legacy-B-facet", "tenant-B");
    let raw_id = raw.id;
    store.create_facet(&raw).await.unwrap();

    // Tenant-A caller cannot see it.
    let alice_ctx = ctx_for("alice", "tenant-A");
    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;

    let err = alice_gate.get(raw_id).await.unwrap_err();
    assert!(matches!(err, GateError::NotFound));

    let listed = alice_gate.list_children(None).await.unwrap();
    assert!(!listed.iter().any(|f| f.id == raw_id));
}
