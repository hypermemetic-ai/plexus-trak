//! UT-W3 cutover suite.
//!
//! Three concerns, each pinned to its driving artifact:
//!
//! 1. **Anonymous-mutation coverage** (defect 88f9bcb6 AC2): enumerate
//!    every mutating method on the facet / discuss / identity hubs and
//!    assert each rejects an anonymous call with the standard
//!    authentication-required error at dispatch. Reads stay
//!    anonymous-tolerant (the documented read posture: anonymous callers
//!    see PUBLIC facets only; localhost-dev friendly).
//!
//! 2. **session_id regression** (the `is_authenticated()` quirk UT-1
//!    flagged): the old `try_jwt` minted `session_id = ""`, so even
//!    validly token-authed callers failed `AuthContext::is_authenticated`
//!    and the tenant gate treated them as anonymous (no writes). OIDC
//!    contexts now carry a real session id (`sid` claim if present, else
//!    `jti`, else the token's signature segment) and resolve a tenant.
//!
//! 3. **Gate-adapter equivalence** (UT-1 AC2): with trak's `TenantGate`
//!    now a thin adapter over `plexus_auth_core_ut1::TenantGate`, the
//!    wire-visible isolation contract is unchanged — cross-tenant read →
//!    `not_found`, cross-tenant write → `forbidden` — proven end-to-end
//!    through the activation dispatch with OIDC-minted AuthContexts.

mod common;

use std::sync::Arc;

use futures::StreamExt;
use plexus_core::plexus::{
    Activation, AuthContext, PlexusError, PlexusStreamItem, SessionValidator,
};
use plexus_trak::hubs::discuss::DiscussHub;
use plexus_trak::hubs::facet::FacetHub;
use plexus_trak::hubs::identity::IdentityHub;
use plexus_trak::store::discuss::DiscussStore;
use plexus_trak::store::identity::IdentityStore;
use plexus_trak::store::sqlite::SqliteStore;
use serde_json::{json, Value};
use tempfile::TempDir;

// ─── Fixtures ────────────────────────────────────────────────────────────

async fn temp_store() -> (Arc<SqliteStore>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("utw3.db");
    let store = SqliteStore::new(db_path.to_str().unwrap()).await.unwrap();
    (Arc::new(store), dir)
}

/// Authenticate an OIDC token through the real `TrakAuth` chain and hand
/// back the handlers' `AuthContext` — exactly what the WS perimeter does.
async fn ctx_for(store: &Arc<SqliteStore>, user: &str, org: &str) -> AuthContext {
    let identity = IdentityStore::new(store.pool().clone());
    let auth = common::fixture_trak_auth(identity);
    auth.validate(&common::mint_for(user, Some(org)))
        .await
        .expect("fixture token must validate")
}

/// Drain a PlexusStream and return the deserialized Data contents.
async fn drain(stream: plexus_core::plexus::PlexusStream) -> Vec<Value> {
    stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .filter_map(|item| match item {
            PlexusStreamItem::Data { content, .. } => Some(content),
            _ => None,
        })
        .collect()
}

/// First event's `type` and (optional) `code` fields.
fn first_type_code(events: &[Value]) -> (String, Option<String>) {
    let first = events.first().expect("stream must emit at least one event");
    (
        first.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        first.get("code").and_then(|v| v.as_str()).map(str::to_string),
    )
}

// ─── 1. Anonymous-mutation coverage (defect 88f9bcb6 AC2) ────────────────

/// Every mutating method, per hub. THIS LIST IS THE COVERAGE CONTRACT:
/// when a new mutating method is added to a hub, add it here (the
/// companion `*_methods_accounted_for` test fails if the hub grows a
/// method this file has not classified).
const FACET_MUTATING: &[&str] = &[
    "create",
    "update",
    "delete",
    "move_to",
    "link",
    "unlink",
    "checkout", // writes the working tree
    "flush",    // writes the store from the working tree
    "import_plans",
];
const FACET_READS: &[&str] = &[
    "get", "list", "tree", "links", "blocked", "search", "grep", "diff",
];

const DISCUSS_MUTATING: &[&str] = &["comment", "update", "delete"];
const DISCUSS_READS: &[&str] = &["list", "get"];

const IDENTITY_MUTATING_AUTHED: &[&str] = &["create_api_key", "revoke_api_key"];
// register / login / refresh / srp_* mint or bootstrap identity and are
// anonymous BY DESIGN; me / list_api_keys / list_users are authed reads.

#[tokio::test]
async fn anonymous_mutations_rejected_across_all_hubs() {
    let (store, _dir) = temp_store().await;
    let facet_hub = FacetHub::new(store.clone());

    let discuss_store = Arc::new(DiscussStore::new(store.pool().clone()));
    discuss_store.migrate().await.unwrap();
    let discuss_hub = DiscussHub::new(discuss_store);

    let identity_hub = IdentityHub::new(
        IdentityStore::new(store.pool().clone()),
        b"test-secret-32-bytes-minimum-len".to_vec(),
    );

    // The dispatch-level auth gate runs BEFORE param extraction, so empty
    // params suffice; the assertion is on the dispatch result itself.
    for method in FACET_MUTATING {
        let res = facet_hub.call(method, json!({}), None, None).await;
        assert!(
            matches!(res, Err(PlexusError::Unauthenticated(_))),
            "facet.{method} must reject anonymous callers with the standard \
             auth-required error, got: {:?}",
            res.err()
        );
    }

    for method in DISCUSS_MUTATING {
        let res = discuss_hub.call(method, json!({}), None, None).await;
        assert!(
            matches!(res, Err(PlexusError::Unauthenticated(_))),
            "discuss.{method} must reject anonymous callers, got: {:?}",
            res.err()
        );
    }

    for method in IDENTITY_MUTATING_AUTHED {
        let res = identity_hub.call(method, json!({}), None, None).await;
        assert!(
            matches!(res, Err(PlexusError::Unauthenticated(_))),
            "identity.{method} must reject anonymous callers, got: {:?}",
            res.err()
        );
    }
}

#[tokio::test]
async fn anonymous_reads_are_tolerated() {
    // The documented read posture (88f9bcb6: "decide and document"):
    // reads are anonymous-tolerant; the tenant gate scopes anonymous
    // callers to PUBLIC facets. Dispatch must NOT bounce them.
    let (store, _dir) = temp_store().await;
    let facet_hub = FacetHub::new(store.clone());

    let discuss_store = Arc::new(DiscussStore::new(store.pool().clone()));
    discuss_store.migrate().await.unwrap();
    let discuss_hub = DiscussHub::new(discuss_store);

    let facet_read_params: &[(&str, Value)] = &[
        ("get", json!({"id": uuid::Uuid::new_v4().to_string()})),
        ("list", json!({})),
        ("tree", json!({"id": uuid::Uuid::new_v4().to_string()})),
        ("links", json!({"id": uuid::Uuid::new_v4().to_string()})),
        ("blocked", json!({})),
        ("search", json!({"query": "anything"})),
        ("grep", json!({"pattern": "anything"})),
    ];
    for (method, params) in facet_read_params {
        let res = facet_hub.call(method, params.clone(), None, None).await;
        assert!(
            !matches!(res, Err(PlexusError::Unauthenticated(_))),
            "facet.{method} (read) must stay anonymous-tolerant"
        );
    }

    // facet.diff requires auth today (it takes &AuthContext) — it reads
    // the WORKING TREE, not the store; leaving it forced-auth is the
    // conservative posture. Pin it so a change is deliberate:
    let res = facet_hub.call("diff", json!({"path": "/tmp/x"}), None, None).await;
    assert!(matches!(res, Err(PlexusError::Unauthenticated(_))));

    for method in DISCUSS_READS {
        let res = discuss_hub
            .call(
                method,
                json!({"facet_id": uuid::Uuid::new_v4().to_string(), "id": uuid::Uuid::new_v4().to_string()}),
                None,
                None,
            )
            .await;
        assert!(
            !matches!(res, Err(PlexusError::Unauthenticated(_))),
            "discuss.{method} (read) must stay anonymous-tolerant"
        );
    }
}

#[tokio::test]
async fn facet_and_discuss_methods_accounted_for() {
    // Coverage-contract guard: every method the hubs expose must be
    // classified in the constant lists above (so a new mutating method
    // cannot ship unexamined).
    let (store, _dir) = temp_store().await;
    let facet_hub = FacetHub::new(store.clone());
    let discuss_store = Arc::new(DiscussStore::new(store.pool().clone()));
    let discuss_hub = DiscussHub::new(discuss_store);

    let classified: Vec<&str> = FACET_MUTATING
        .iter()
        .chain(FACET_READS.iter())
        .copied()
        .collect();
    for m in facet_hub.methods() {
        if m == "schema" {
            continue; // macro-provided introspection
        }
        assert!(
            classified.contains(&m),
            "facet.{m} is not classified as mutating or read in the \
             anonymous-coverage contract — classify it"
        );
    }

    let classified: Vec<&str> = DISCUSS_MUTATING
        .iter()
        .chain(DISCUSS_READS.iter())
        .copied()
        .collect();
    for m in discuss_hub.methods() {
        if m == "schema" {
            continue;
        }
        assert!(
            classified.contains(&m),
            "discuss.{m} is not classified in the anonymous-coverage contract"
        );
    }
}

// ─── 2. session_id regression (the is_authenticated quirk) ───────────────

#[tokio::test]
async fn oidc_context_carries_real_session_id_and_writes_succeed() {
    // Pre-UT-W3: try_jwt minted session_id = "" → is_authenticated()
    // false → the tenant gate resolved NO tenant for token-authed
    // callers → all gated writes failed. This is the regression pin.
    let (store, _dir) = temp_store().await;

    // Token WITHOUT a sid claim: the pinned fallback (jti, else the
    // signature segment) must still produce a non-empty session id.
    let ctx = ctx_for(&store, "alice", "org_acme").await;
    assert!(!ctx.session_id.is_empty(), "OIDC context must carry a session id");
    assert!(ctx.is_authenticated(), "OIDC context must be authenticated");

    // Token WITH a sid claim: sid wins.
    let identity = IdentityStore::new(store.pool().clone());
    let auth = common::fixture_trak_auth(identity);
    let mut c = common::claims();
    c.insert("sid".into(), json!("sess-oidc-42"));
    let token = common::mint(common::KID_1, common::KEY_1_PEM, c);
    let ctx_sid = auth.validate(&token).await.unwrap();
    assert_eq!(ctx_sid.session_id, "sess-oidc-42");

    // And the consequence the quirk used to break: a gated write through
    // the real dispatch SUCCEEDS for a token-authed caller.
    let facet_hub = FacetHub::new(store.clone());
    let stream = facet_hub
        .call("create", json!({"title": "written by oidc"}), Some(&ctx), None)
        .await
        .expect("authed create must dispatch");
    let events = drain(stream).await;
    let (ty, code) = first_type_code(&events);
    assert_eq!(
        ty, "facet_created",
        "token-authed create must succeed (got {ty} {code:?}) — the \
         empty-session_id quirk would have made this 'unauthenticated'"
    );
    // The gate stamped the caller's resolved tenant (org_id claim).
    assert_eq!(
        events[0]["facet"]["meta"]["tenant"].as_str(),
        Some("org_acme"),
        "created facet must be stamped with the caller's org_id-resolved tenant"
    );
}

// ─── 2b. identity.me answers from OIDC claims (defect bdf7d5f9) ──────────

#[tokio::test]
async fn identity_me_answers_from_oidc_claims_without_db_lookup() {
    // Defect bdf7d5f9: post-cutover the OIDC validator mints a verified
    // identity from RS256 claims (sub/username/org_id), but `identity.me`
    // still did a local users-table lookup by that sub — and the IdP
    // subject is NOT a trak users row. The lookup failed with
    // `user_lookup_failed: ... user not found: <idp-sub>`, surfacing as
    // the UIs' boot-error banner on reload. The fix: `me` returns the
    // verified claims straight from the AuthContext for OIDC callers, no
    // DB round-trip.
    let (store, _dir) = temp_store().await;
    let identity_hub = IdentityHub::new(
        IdentityStore::new(store.pool().clone()),
        b"test-secret-32-bytes-minimum-len".to_vec(),
    );

    // OIDC context whose `sub` has NO corresponding trak users row — the
    // store is empty, so any get_user_by_id would error. (`ctx_for`
    // authenticates a fixture RS256 token through the real TrakAuth.)
    let ctx = ctx_for(&store, "idp-subject-no-local-row", "org_acme").await;
    assert_eq!(ctx.get_metadata_string("auth_method").as_deref(), Some("oidc"));

    let events = drain(
        identity_hub
            .call("me", json!({}), Some(&ctx), None)
            .await
            .expect("authed me must dispatch"),
    )
    .await;

    let (ty, code) = first_type_code(&events);
    assert_eq!(
        ty, "user_info",
        "me must answer from claims (got {ty} {code:?}) — the DB lookup \
         on the IdP sub would have yielded user_lookup_failed"
    );
    let info = &events[0];
    assert_eq!(info["user_id"].as_str(), Some("idp-subject-no-local-row"));
    assert_eq!(info["username"].as_str(), Some("idp-subject-no-local-row"));
    // org_id resolves through the tenant_id dual-key alias.
    assert_eq!(info["tenant"].as_str(), Some("org_acme"));
    assert_eq!(
        info["roles"].as_array().map(|r| r.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
        Some(vec!["user"]),
    );
}

// ─── 3. Gate-adapter equivalence, end-to-end through dispatch ────────────

#[tokio::test]
async fn cross_tenant_read_is_not_found_and_write_is_forbidden() {
    let (store, _dir) = temp_store().await;
    let facet_hub = FacetHub::new(store.clone());

    let alice = ctx_for(&store, "alice", "org_a").await;
    let bob = ctx_for(&store, "bob", "org_b").await;

    // Alice creates a facet in org_a.
    let events = drain(
        facet_hub
            .call("create", json!({"title": "alice's secret"}), Some(&alice), None)
            .await
            .unwrap(),
    )
    .await;
    let (ty, _) = first_type_code(&events);
    assert_eq!(ty, "facet_created");
    let facet_id = events[0]["facet"]["id"].as_str().unwrap().to_string();

    // Bob reads it by UUID → not_found (existence-oracle defense).
    let events = drain(
        facet_hub
            .call("get", json!({"id": facet_id}), Some(&bob), None)
            .await
            .unwrap(),
    )
    .await;
    let (ty, code) = first_type_code(&events);
    assert_eq!(ty, "error");
    assert_eq!(code.as_deref(), Some("not_found"), "cross-tenant read must be not_found");

    // Bob updates it → forbidden (existence already conceded on writes).
    let events = drain(
        facet_hub
            .call(
                "update",
                json!({"id": facet_id, "title": "bob owns this now"}),
                Some(&bob),
                None,
            )
            .await
            .unwrap(),
    )
    .await;
    let (ty, code) = first_type_code(&events);
    assert_eq!(ty, "error");
    assert_eq!(code.as_deref(), Some("forbidden"), "cross-tenant write must be forbidden");

    // Alice still sees her unmodified facet.
    let events = drain(
        facet_hub
            .call("get", json!({"id": facet_id}), Some(&alice), None)
            .await
            .unwrap(),
    )
    .await;
    let (ty, _) = first_type_code(&events);
    assert_eq!(ty, "facet_detail");
    assert_eq!(events[0]["facet"]["title"].as_str(), Some("alice's secret"));
}

#[tokio::test]
async fn anonymous_get_sees_public_but_not_tenant_owned() {
    // The read posture, end-to-end: anonymous get of a PUBLIC facet
    // works; anonymous get of a tenant-owned facet is not_found.
    let (store, _dir) = temp_store().await;
    let facet_hub = FacetHub::new(store.clone());

    // Tenant-owned facet via the gate.
    let alice = ctx_for(&store, "alice", "org_a").await;
    let events = drain(
        facet_hub
            .call("create", json!({"title": "tenanted"}), Some(&alice), None)
            .await
            .unwrap(),
    )
    .await;
    let owned_id = events[0]["facet"]["id"].as_str().unwrap().to_string();

    // Public facet straight through the store (the gate never creates
    // public facets — caller's tenant always wins on create).
    use plexus_trak::store::FacetStore;
    let now = chrono::Utc::now();
    let public = plexus_trak::types::Facet {
        id: uuid::Uuid::new_v4(),
        parent_id: None,
        title: "public-doc".into(),
        body: None,
        status: "open".into(),
        owner: "anyone".into(),
        meta: plexus_trak::types::FacetMeta::default(),
        created_at: now,
        updated_at: now,
    };
    store.create_facet(&public).await.unwrap();

    let events = drain(
        facet_hub
            .call("get", json!({"id": public.id.to_string()}), None, None)
            .await
            .expect("anonymous get must dispatch"),
    )
    .await;
    let (ty, _) = first_type_code(&events);
    assert_eq!(ty, "facet_detail", "anonymous caller must read public facets");

    let events = drain(
        facet_hub
            .call("get", json!({"id": owned_id}), None, None)
            .await
            .unwrap(),
    )
    .await;
    let (ty, code) = first_type_code(&events);
    assert_eq!(ty, "error");
    assert_eq!(code.as_deref(), Some("not_found"), "anonymous read of tenant-owned facet must be not_found");
}
