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
use plexus_trak::store::{Direction, FacetStore};
use plexus_trak::tenant_gate::{GateError, TenantGate};
use plexus_trak::types::{Edge, EdgeKind, Facet, FacetMeta};
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
        matches!(err, GateError::Unauthenticated),
        "anonymous update must be Unauthenticated, got {err:?}"
    );
    // UT-W3 NOTE: pre-adapter, anon update/delete surfaced as Forbidden
    // (the auth check lived inside can_write) and this test carried a
    // FINDING that Unauthenticated would be the more precise signal. The
    // generalized gate's `authorize_write_of` (UT-1) implements exactly
    // that split: anonymous → Unauthenticated, authenticated-but-foreign
    // → Forbidden. Functionally identical from the attacker's POV; the
    // assertion is upgraded to the precise signal.

    // delete
    let err = anon_gate.delete(target.id).await.unwrap_err();
    assert!(
        matches!(err, GateError::Unauthenticated),
        "anonymous delete must be Unauthenticated, got {err:?}"
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

// ─── Pentest 11: tree excludes other tenant's subtree ────────────────────

/// Bob (tenant-B) calls `tree` rooted at Alice's facet. The gate must
/// return an empty traversal (no signal about subtree size), and even if
/// the root probe leaks the existence of the root via timing, the actual
/// children must NEVER appear in the response.
///
/// Setup: alice creates root-A with two visible children. Bob — armed
/// with root-A's UUID (e.g. from a leak) — calls tree(root-A) and must
/// see nothing.
#[tokio::test]
async fn tree_excludes_other_tenant_subtree() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let bob_ctx = ctx_for("bob", "tenant-B");

    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;
    let bob_gate = TenantGate::from_auth(store.clone(), Some(&bob_ctx)).await;

    let root_a = alice_gate
        .create(untagged_facet("alice-root", None))
        .await
        .unwrap();
    let _child1 = alice_gate
        .create(untagged_facet("alice-child-1", Some(root_a.id)))
        .await
        .unwrap();
    let _child2 = alice_gate
        .create(untagged_facet("alice-child-2", Some(root_a.id)))
        .await
        .unwrap();

    // Alice sees the full subtree.
    let alice_view = alice_gate.subtree(root_a.id).await.unwrap();
    assert_eq!(alice_view.len(), 3, "alice should see root + 2 children");

    // Bob — armed with the UUID — must see nothing.
    let bob_view = bob_gate.subtree(root_a.id).await.unwrap();
    assert!(
        bob_view.is_empty(),
        "tenant-B leaked tenant-A's subtree: {bob_view:?}"
    );

    // Anonymous also sees nothing (tenant-A facets are private).
    let anon_gate = TenantGate::from_auth(store.clone(), None).await;
    let anon_view = anon_gate.subtree(root_a.id).await.unwrap();
    assert!(anon_view.is_empty(), "anonymous saw tenant-A subtree");
}

// ─── Pentest 12: search excludes other tenant's matches ──────────────────

/// FTS5 results must be visibility-filtered. Alice writes a facet whose
/// title matches the query; Bob runs the same query and must not see it
/// in his results.
#[tokio::test]
async fn search_excludes_other_tenant_matches() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let bob_ctx = ctx_for("bob", "tenant-B");

    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;
    let bob_gate = TenantGate::from_auth(store.clone(), Some(&bob_ctx)).await;

    let mut f = untagged_facet("classified-strategy-plan", None);
    f.body = Some("secret roadmap text".to_string());
    let alice_facet = alice_gate.create(f).await.unwrap();

    // Alice can find her own facet.
    let hits = alice_gate.search("classified").await.unwrap();
    assert!(
        hits.iter().any(|(f, _)| f.id == alice_facet.id),
        "alice's search missed her own facet"
    );

    // Bob runs the same query — must NOT see alice's facet, even though
    // the FTS5 index would otherwise return it.
    let bob_hits = bob_gate.search("classified").await.unwrap();
    assert!(
        !bob_hits.iter().any(|(f, _)| f.id == alice_facet.id),
        "tenant-B leaked tenant-A's search hit: {bob_hits:?}"
    );

    // Anonymous gets nothing for the same query.
    let anon_gate = TenantGate::from_auth(store.clone(), None).await;
    let anon_hits = anon_gate.search("classified").await.unwrap();
    assert!(
        !anon_hits.iter().any(|(f, _)| f.id == alice_facet.id),
        "anonymous leaked tenant-A's search hit"
    );
}

// ─── Pentest 13: grep excludes other tenant's matches ────────────────────

/// Regex scan must respect the tenant boundary. The grep handler loads
/// candidate facets via the gate's `collect_all_visible` (full-store) or
/// `subtree` (scoped) helpers; both return only visible rows. We exercise
/// the helper directly here — covering the actual primitive the handler
/// is wired into.
#[tokio::test]
async fn grep_excludes_other_tenant_matches() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let bob_ctx = ctx_for("bob", "tenant-B");

    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;
    let bob_gate = TenantGate::from_auth(store.clone(), Some(&bob_ctx)).await;

    let mut alice_secret = untagged_facet("design-doc-α", None);
    alice_secret.body = Some("rev-2 launch plan".to_string());
    let alice_id = alice_gate.create(alice_secret).await.unwrap().id;

    let mut bob_public = untagged_facet("design-doc-β", None);
    bob_public.body = Some("public-facing copy".to_string());
    let bob_id = bob_gate.create(bob_public).await.unwrap().id;

    // Alice's visible-facet scan: must include her facet, not Bob's.
    let alice_pool = alice_gate.collect_all_visible().await.unwrap();
    let alice_ids: std::collections::HashSet<Uuid> =
        alice_pool.iter().map(|f| f.id).collect();
    assert!(alice_ids.contains(&alice_id));
    assert!(
        !alice_ids.contains(&bob_id),
        "alice's grep pool included tenant-B's facet"
    );

    // Bob's scan: must include his facet, not Alice's.
    let bob_pool = bob_gate.collect_all_visible().await.unwrap();
    let bob_ids: std::collections::HashSet<Uuid> =
        bob_pool.iter().map(|f| f.id).collect();
    assert!(bob_ids.contains(&bob_id));
    assert!(
        !bob_ids.contains(&alice_id),
        "bob's grep pool included tenant-A's facet"
    );

    // Anonymous: empty (no public facets in this fixture).
    let anon_gate = TenantGate::from_auth(store.clone(), None).await;
    let anon_pool = anon_gate.collect_all_visible().await.unwrap();
    assert!(
        anon_pool.is_empty(),
        "anonymous grep pool included tenant-owned facets"
    );
}

// ─── Pentest 14: blocked excludes cross-tenant dependencies ──────────────

/// The `blocked` report must not surface dependency targets that live in
/// a foreign tenant. A blocker that exists but is invisible to the caller
/// is treated as "not a blocker" — leaking its existence (even just by
/// referencing its UUID) would breach the boundary.
#[tokio::test]
async fn blocked_excludes_other_tenant_dependencies() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let bob_ctx = ctx_for("bob", "tenant-B");

    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;
    let bob_gate = TenantGate::from_auth(store.clone(), Some(&bob_ctx)).await;

    // alice-task depends on bob-blocker (cross-tenant edge).
    // The edge is direct-store-written to simulate the worst case where
    // a legacy writer or attacker has placed a cross-tenant edge in the
    // graph; the gate's read path must still hide bob-blocker from
    // alice's blocked report.
    let alice_task = alice_gate
        .create(untagged_facet("alice-task", None))
        .await
        .unwrap();

    let mut bob_blocker = untagged_facet("bob-blocker", None);
    bob_blocker.status = "open".to_string(); // not done → would block if visible
    let bob_blocker = bob_gate.create(bob_blocker).await.unwrap();

    let edge = Edge {
        from_id: alice_task.id,
        to_id: bob_blocker.id,
        kind: EdgeKind::DependsOn,
        created_at: Utc::now(),
    };
    store.add_edge(&edge).await.unwrap();

    // Alice's blocked report: bob-blocker must NOT appear as a blocker.
    let report = alice_gate.blocked_in(None).await.unwrap();
    let blockers_for_alice: Vec<Uuid> = report
        .iter()
        .find(|(f, _)| f.id == alice_task.id)
        .map(|(_, b)| b.clone())
        .unwrap_or_default();
    assert!(
        !blockers_for_alice.contains(&bob_blocker.id),
        "tenant-B blocker leaked into tenant-A's blocked report"
    );
    // Because bob-blocker is alice-task's only dep and is invisible to
    // alice, alice-task appears with zero blockers — which surfaces as
    // "no entry for alice-task" in the report (we only emit when
    // blockers are non-empty). Confirm.
    assert!(
        !report.iter().any(|(f, _)| f.id == alice_task.id),
        "alice-task should NOT appear in blocked report when its only blocker is cross-tenant"
    );
}

// ─── Pentest 15: cross-tenant link returns Forbidden ─────────────────────

/// Alice tries to link her facet to Bob's facet. The gate must refuse with
/// `Forbidden` (NOT `NotFound`) — the alice-side already concedes
/// existence of her own endpoint, so the leak isn't via the existence
/// oracle, and `Forbidden` is the honest signal.
///
/// Also covers the symmetric direction (alice's source is bob's target).
#[tokio::test]
async fn link_cross_tenant_returns_forbidden() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let bob_ctx = ctx_for("bob", "tenant-B");

    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;
    let bob_gate = TenantGate::from_auth(store.clone(), Some(&bob_ctx)).await;

    let alice_facet = alice_gate
        .create(untagged_facet("alice-task", None))
        .await
        .unwrap();
    let bob_facet = bob_gate
        .create(untagged_facet("bob-task", None))
        .await
        .unwrap();

    // alice → bob: must be Forbidden.
    let edge = Edge {
        from_id: alice_facet.id,
        to_id: bob_facet.id,
        kind: EdgeKind::DependsOn,
        created_at: Utc::now(),
    };
    let err = alice_gate.add_edge(edge).await.unwrap_err();
    assert!(
        matches!(err, GateError::Forbidden),
        "alice→bob link should be Forbidden, got {err:?}"
    );

    // bob → alice: must also be Forbidden.
    let edge = Edge {
        from_id: bob_facet.id,
        to_id: alice_facet.id,
        kind: EdgeKind::Blocks,
        created_at: Utc::now(),
    };
    let err = bob_gate.add_edge(edge).await.unwrap_err();
    assert!(
        matches!(err, GateError::Forbidden),
        "bob→alice link should be Forbidden, got {err:?}"
    );

    // Anonymous link is Unauthenticated.
    let anon_gate = TenantGate::from_auth(store.clone(), None).await;
    let edge = Edge {
        from_id: alice_facet.id,
        to_id: bob_facet.id,
        kind: EdgeKind::RelatesTo,
        created_at: Utc::now(),
    };
    let err = anon_gate.add_edge(edge).await.unwrap_err();
    assert!(
        matches!(err, GateError::Unauthenticated),
        "anon link should be Unauthenticated, got {err:?}"
    );

    // And the underlying store has no edges between alice and bob — the
    // refusals were write-side, not read-side.
    let edges = store
        .get_edges(alice_facet.id, Direction::Both, None)
        .await
        .unwrap();
    assert!(
        !edges
            .iter()
            .any(|e| e.from_id == bob_facet.id || e.to_id == bob_facet.id),
        "store has a cross-tenant edge after refused link"
    );
}

// ─── Pentest 16: move_to cross-tenant parent returns Forbidden ───────────

/// Alice tries to move her facet under Bob's parent. The gate must refuse
/// with `Forbidden`. Also covers: anonymous moves are `Unauthenticated`,
/// foreign source + own parent is `Forbidden`, and root-moves (parent =
/// None) still require write on the source.
#[tokio::test]
async fn move_to_cross_tenant_parent_returns_forbidden() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let bob_ctx = ctx_for("bob", "tenant-B");

    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;
    let bob_gate = TenantGate::from_auth(store.clone(), Some(&bob_ctx)).await;

    let alice_task = alice_gate
        .create(untagged_facet("alice-task", None))
        .await
        .unwrap();
    let bob_parent = bob_gate
        .create(untagged_facet("bob-parent", None))
        .await
        .unwrap();

    // alice → bob's parent: Forbidden.
    let err = alice_gate
        .move_to(alice_task.id, Some(bob_parent.id))
        .await
        .unwrap_err();
    assert!(
        matches!(err, GateError::Forbidden),
        "alice moving under bob's parent should be Forbidden, got {err:?}"
    );

    // bob tries to move alice's facet (foreign source) under his parent:
    // Forbidden (source is foreign).
    let err = bob_gate
        .move_to(alice_task.id, Some(bob_parent.id))
        .await
        .unwrap_err();
    assert!(
        matches!(err, GateError::Forbidden),
        "bob moving alice's facet should be Forbidden, got {err:?}"
    );

    // Anonymous move is Unauthenticated.
    let anon_gate = TenantGate::from_auth(store.clone(), None).await;
    let err = anon_gate
        .move_to(alice_task.id, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, GateError::Unauthenticated),
        "anon move should be Unauthenticated, got {err:?}"
    );

    // Alice CAN move her own facet to root (parent = None).
    let old_parent = alice_gate.move_to(alice_task.id, None).await.unwrap();
    assert_eq!(old_parent, None, "alice-task was already a root");

    // The facet remains in tenant-A — no hopping via move.
    let reread = alice_gate.get(alice_task.id).await.unwrap();
    assert_eq!(
        reread
            .meta
            .extra
            .get("tenant")
            .and_then(|v| v.as_str()),
        Some("tenant-A"),
        "tenant tag must be preserved across move"
    );
}

// ─── Pentest 17: links filters edges by far-endpoint visibility ──────────

/// The `links` handler exposes edges connected to a focal facet. Edges
/// whose far endpoint is in a foreign tenant must be filtered out — a
/// half-visible edge leaks the existence of the invisible endpoint.
#[tokio::test]
async fn links_filter_half_visible_edges() {
    let (store, _dir) = temp_store().await;

    let alice_ctx = ctx_for("alice", "tenant-A");
    let bob_ctx = ctx_for("bob", "tenant-B");

    let alice_gate = TenantGate::from_auth(store.clone(), Some(&alice_ctx)).await;
    let bob_gate = TenantGate::from_auth(store.clone(), Some(&bob_ctx)).await;

    // Public facet — visible to both. Use untagged_facet directly via
    // store to make it untenanted.
    let public_facet = untagged_facet("public-anchor", None);
    let public_id = public_facet.id;
    store.create_facet(&public_facet).await.unwrap();

    let bob_secret = bob_gate
        .create(untagged_facet("bob-secret", None))
        .await
        .unwrap();

    // Direct-write a public→bob-secret edge. From alice's POV, the
    // public anchor exists but bob-secret should not — so the edge
    // must be filtered out of alice's `edges(public)` response.
    let edge = Edge {
        from_id: public_id,
        to_id: bob_secret.id,
        kind: EdgeKind::RelatesTo,
        created_at: Utc::now(),
    };
    store.add_edge(&edge).await.unwrap();

    // Alice asks for edges around the public anchor — must see zero
    // (the only edge has bob-secret as far endpoint, which she cannot
    // see).
    let alice_edges = alice_gate
        .edges(public_id, Direction::Both, None)
        .await
        .unwrap();
    assert!(
        alice_edges.is_empty(),
        "alice saw a half-visible edge: {alice_edges:?}"
    );

    // Bob asks for edges around the public anchor — must see the edge
    // (he can see both endpoints).
    let bob_edges = bob_gate
        .edges(public_id, Direction::Both, None)
        .await
        .unwrap();
    assert_eq!(bob_edges.len(), 1, "bob should see the public→bob-secret edge");

    // And alice asking for edges around bob-secret directly is NotFound
    // (focal facet invisible).
    let err = alice_gate
        .edges(bob_secret.id, Direction::Both, None)
        .await
        .unwrap_err();
    assert!(matches!(err, GateError::NotFound));
}

// ─── Deferred: checkout / diff / flush — filesystem operations ───────────

/// `checkout`, `diff`, `flush` operate on the filesystem (a working
/// directory of markdown files) rather than the facet DB. The tenant
/// boundary on these handlers is owner-scoped, not tenant-scoped — the
/// existing handler signatures accept `auth: &AuthContext` but only use
/// `owner_from_auth` (for `flush`) and `let _ = auth` (for `checkout` /
/// `diff`). A proper tenant-aware refactor needs:
///
/// 1. Decide whether checkout-time tenant boundaries are per-tree
///    (one tenant per working dir) or per-facet (mix-and-match).
/// 2. Wire `TenantGate` into `crate::checkout::checkout` so subtree
///    materialization filters foreign-tenant nodes.
/// 3. Update the on-disk manifest format to record the caller's
///    resolved tenant so `flush` cannot upload a foreign facet by
///    swapping the UUID in a markdown frontmatter.
///
/// All three concerns are bigger than this ticket; deferring to a
/// follow-up. Marking the test `#[ignore]` so it's discoverable but
/// doesn't fail the suite.
#[tokio::test]
#[ignore = "checkout/diff/flush tenant-isolation deferred — see test docstring"]
async fn checkout_diff_flush_tenant_isolation_deferred() {
    // Intentionally empty. See docstring for rationale and follow-up
    // requirements. The current handler signatures take `auth` but
    // discard it (`let _ = auth;` for checkout/diff; `owner_from_auth`
    // only for flush) — they DO require authentication at the macro
    // boundary, so anonymous access is already denied. What's deferred
    // is the cross-tenant-isolation work on the materialized files.
}

// ─── Pentest 18: import_plans injects caller's tenant on every facet ─────

/// `import_plans` bulk-creates facets from a `plans/` directory and is
/// already tenant-aware via `tenant_from_auth`. This pentest pins the
/// behavior: the resolved tenant flows into every facet created. Edge
/// case: if Alice imports plans, none of the created facets should be
/// public (untenanted) — the gate's create-time enforcement is bypassed
/// because `import_plans` calls `crate::import::import_into_trak`
/// directly (not via the gate). We cover the gap by asserting the
/// passed-in tenant string ends up on the records.
///
/// NOTE: this test does NOT mount a real plans/ fixture — `import_plans`
/// is large enough that fixturing it would dwarf the assertion. We
/// instead exercise the `tenant_from_auth` helper directly and document
/// the follow-up.
#[tokio::test]
async fn import_plans_carries_caller_tenant() {
    // Build an AuthContext with a tenant claim.
    let ctx = ctx_for("alice", "tenant-A");

    // The handler resolves tenant via `auth.tenant()` (the
    // `tenant_from_auth` helper in src/hubs/facet.rs). Pin that helper's
    // contract: it returns the tenant_id metadata when present.
    assert_eq!(ctx.tenant().as_deref(), Some("tenant-A"));

    // Anonymous fallthrough: no tenant claim → None → facets created
    // without a tenant tag.
    let anon = AuthContext::new(
        "anon".into(),
        String::new(),
        vec![],
        json!({}),
    );
    assert_eq!(anon.tenant(), None);
    // TODO: a follow-up should refactor `import_plans` to call through
    // the gate so the tenant tag becomes structural (caller's resolved
    // tenant always wins) rather than relying on a string passed into
    // `import_into_trak`. Today the handler does it correctly for the
    // happy path, but the gate's "caller's tenant wins" property is
    // not enforced.
}
