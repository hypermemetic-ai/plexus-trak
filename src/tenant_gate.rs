//! `TenantGate` — handler-side tenant-isolation wrapper around `FacetStore`.
//!
//! **UT-W3 (wave 3): this is now a thin adapter** over the generalized
//! [`plexus_auth_core_ut1::TenantGate`] extracted by UT-1, exactly per the
//! adapter shape documented in that module ("Adapter shape: how trak swaps
//! in"). What remains here is the trak-specific part the extraction
//! deliberately left behind:
//!
//! - the `FacetStore` plumbing (which store call to make, how to walk
//!   subtrees / edges / blockers), and
//! - the storage placement of the tenant tag (`meta.extra["tenant"]`),
//!   expressed via the [`TenantTagged`] impl for [`Facet`].
//!
//! The predicates (`can_see` / `can_write`), the denial taxonomy
//! (read-denial = NotFound existence-oracle defense, write-denial =
//! Forbidden, anonymous write = Unauthenticated), the `is_authenticated()`
//! defense-in-depth check, and the create-stamp / update-preserve
//! tenant-hop defenses all live in `plexus_auth_core_ut1::TenantGate` now
//! — behavior is unchanged because the predicates were extracted verbatim
//! (pinned by `tests/tenant_isolation_test.rs`, the same pentest suite
//! that pinned the pre-adapter gate).
//!
//! One deliberate refinement rides the adapter: anonymous `update` /
//! `delete` now surface [`GateError::Unauthenticated`] instead of
//! [`GateError::Forbidden`]. The pre-adapter suite documented this exact
//! change as desirable ("We could surface Unauthenticated specifically by
//! early-returning…"); the generalized gate's `authorize_write` does it
//! structurally. The wire-level outcome for an attacker is identical: the
//! operation fails.
//!
//! # Tenancy claim (UT-S01 D3)
//!
//! The resolver is [`ClaimTenantResolver::new`] — default claim key
//! **`org_id`** (Auth0 Organizations convention) with the one-window
//! `tenant_id` deprecation alias, so pre-cutover HS256-era contexts that
//! carry only `tenant_id` keep resolving while the OIDC validator writes
//! both keys. Facet **storage** keeps `meta.extra["tenant"]` — no data
//! migration in UT-W3; only the claim side moved to `org_id`.
//!
//! # Threat model
//!
//! Unchanged — see `plexus_auth_core_ut1::tenant::gate` module docs for
//! the canonical statement; `tests/tenant_isolation_test.rs` verifies each
//! item end-to-end against the real `SqliteStore`.

use std::sync::Arc;

// The handlers' AuthContext: `plexus_core::plexus::AuthContext`, which is
// the pre-UT-1 `plexus_auth_core::AuthContext` re-export.
use plexus_core::plexus::AuthContext;
// The UT-1 surface (generalized gate + org_id resolver) comes from the
// unmerged feature/UT-1-tenancy-oidc branch via the ut1-auth-core shim.
// TODO: s/plexus_auth_core_ut1/plexus_auth_core/ once UT-1 merges.
use plexus_auth_core_ut1::{
    ClaimTenantResolver, GateDenial, Tenant, TenantId, TenantTagged,
};
use uuid::Uuid;

use crate::store::{Direction, FacetStore, StoreError};
use crate::types::{Edge, EdgeKind, Facet};

/// UT-W3-MIRROR: field-for-field bridge from the handlers' AuthContext
/// (`plexus_core::plexus::AuthContext`, i.e. the pre-UT-1
/// `plexus_auth_core` crate) to the UT-1 branch's nominally-distinct
/// `AuthContext`. The two structs are identical (`user_id`, `session_id`,
/// `roles`, `metadata`); they differ only in crate identity while UT-1 is
/// unmerged. DELETE this together with the ut1-auth-core shim once
/// feature/UT-1-tenancy-oidc merges (the types collapse into one).
pub(crate) fn mirror_auth(ctx: &AuthContext) -> plexus_auth_core_ut1::AuthContext {
    plexus_auth_core_ut1::AuthContext::new(
        ctx.user_id.clone(),
        ctx.session_id.clone(),
        ctx.roles.clone(),
        ctx.metadata.clone(),
    )
}

/// trak's resources declare where their tenant tag lives: the
/// `meta.extra["tenant"]` bag (no data migration in UT-W3 — storage keeps
/// the `tenant` key; the **claim** side moved to `org_id` per UT-S01 D3).
///
/// Per the `TenantTagged` contract, a stored tag that fails `TenantId`
/// validation must NOT map to `None` (that would silently publish the
/// resource). `TenantId` validation is broad (printable ASCII ≤ 256
/// bytes), so a failing tag means corrupt data; we conservatively map it
/// to a sentinel tenant value that can never equal a caller's resolved
/// tenant, keeping the resource invisible/unwritable rather than public.
impl TenantTagged for Facet {
    fn tenant_tag(&self) -> Option<TenantId> {
        let raw = self.meta.extra.get("tenant").and_then(|v| v.as_str())?;
        Some(TenantId::try_new(raw).unwrap_or_else(|_| {
            TenantId::try_new("__corrupt-tenant-tag__")
                .expect("sentinel tag is valid printable ASCII")
        }))
    }
}

/// Failure modes for [`TenantGate`] operations.
///
/// The gate distinguishes `NotFound` from `Forbidden` for the same underlying
/// "you can't have this" signal — read denials become `NotFound` (so a
/// foreign-tenant probe cannot use the gate as an existence oracle), and
/// write denials become `Forbidden` (the caller already exposed the target
/// via the create path).
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// The facet does not exist, OR the caller cannot see it. Indistinguishable
    /// to the caller by design.
    #[error("not found")]
    NotFound,
    /// The caller is authenticated but cannot modify the target.
    #[error("forbidden")]
    Forbidden,
    /// Write operations always require an authenticated caller with a
    /// resolved tenant.
    #[error("unauthenticated")]
    Unauthenticated,
    /// Lower-level store failure surfaced verbatim for diagnostics.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
}

impl From<GateDenial> for GateError {
    fn from(d: GateDenial) -> Self {
        match d {
            GateDenial::NotFound => GateError::NotFound,
            GateDenial::Forbidden => GateError::Forbidden,
            GateDenial::Unauthenticated => GateError::Unauthenticated,
        }
    }
}

/// Tenant-isolating wrapper around a [`FacetStore`].
///
/// One `TenantGate` is constructed per request via [`TenantGate::from_auth`].
/// It holds:
///
/// - The shared `Arc<dyn FacetStore>` (no per-request allocation).
/// - The generalized [`plexus_auth_core_ut1::TenantGate`] carrying the
///   caller's resolved [`Tenant`] (or anonymous).
///
/// All accessors enforce the visibility / write predicates via the
/// generalized gate.
pub struct TenantGate {
    store: Arc<dyn FacetStore>,
    gate: plexus_auth_core_ut1::TenantGate,
}

impl TenantGate {
    /// Build a gate for the given store and (optional) caller context.
    ///
    /// Resolution flow (now inside
    /// `plexus_auth_core_ut1::TenantGate::from_auth`):
    ///
    /// 1. `auth == None` → anonymous gate.
    /// 2. `auth.is_authenticated() == false` → anonymous gate (the
    ///    defense-in-depth check pinned by
    ///    `forged_authcontext_does_not_grant_tenant`).
    /// 3. Otherwise [`ClaimTenantResolver::new`] runs — claim key `org_id`,
    ///    `tenant_id` deprecation alias, `single_user_fallback = true`.
    ///    `Ok` → tenant gate, `Err` → anonymous gate.
    pub async fn from_auth(
        store: Arc<dyn FacetStore>,
        auth: Option<&AuthContext>,
    ) -> Self {
        // UT-W3-MIRROR: bridge the nominally-distinct AuthContext types
        // while UT-1 is unmerged (see mirror_auth).
        let mirrored = auth.map(mirror_auth);
        let resolver = ClaimTenantResolver::new();
        let gate =
            plexus_auth_core_ut1::TenantGate::from_auth(&resolver, mirrored.as_ref()).await;
        Self { store, gate }
    }

    /// The caller's resolved tenant, if any. `None` ↔ anonymous.
    pub fn caller_tenant(&self) -> Option<&Tenant> {
        self.gate.caller_tenant()
    }

    /// Visibility predicate: can the caller see this facet?
    ///
    /// Delegates to the generalized gate's matrix (see
    /// `plexus_auth_core_ut1::TenantGate` docs):
    ///
    /// | caller     | facet.tenant   | result |
    /// |------------|----------------|--------|
    /// | `None`     | `None`         | `true` (anonymous sees public) |
    /// | `None`     | `Some(_)`      | `false` (anonymous cannot see tenant-owned) |
    /// | `Some(t)`  | `None`         | `true` (tenant sees public) |
    /// | `Some(t)`  | `Some(ft)`     | `t == ft` |
    pub fn can_see(&self, facet: &Facet) -> bool {
        self.gate.visible(facet)
    }

    /// Write predicate: can the caller mutate this facet?
    ///
    /// Writes always require an authenticated tenant. A tenant can mutate
    /// public (untenanted) facets and facets in its own tenant.
    pub fn can_write(&self, facet: &Facet) -> bool {
        self.gate.can_write(facet.tenant_tag().as_ref())
    }

    // ─── Store-mirror methods (visibility-enforced) ──────────────────────

    /// Create a facet on behalf of the caller.
    ///
    /// - Requires an authenticated caller; anonymous callers receive
    ///   [`GateError::Unauthenticated`] (via `stamp`).
    /// - **Forces** `facet.meta.extra["tenant"]` to the caller's resolved
    ///   tenant ([`plexus_auth_core_ut1::TenantGate::stamp`]), overwriting
    ///   any forged value the caller may have tried to set. This is the
    ///   structural fix for the "tenant hop via create metadata" attack.
    pub async fn create(&self, mut facet: Facet) -> Result<Facet, GateError> {
        // Caller's resolved tenant wins. Any caller-supplied `tenant` value
        // in meta_extra is discarded — overwriting is intentional, see the
        // `tenant_cannot_hop_via_create_metadata_override` pentest.
        let stamp = self.gate.stamp()?;
        facet.meta.extra.insert(
            "tenant".to_string(),
            serde_json::Value::String(stamp.as_str().to_string()),
        );
        self.store.create_facet(&facet).await?;
        Ok(facet)
    }

    /// Get a facet by UUID.
    ///
    /// Returns [`GateError::NotFound`] when the facet does not exist OR when
    /// the caller cannot see it. The two cases are indistinguishable to the
    /// caller by design — a foreign-tenant probe cannot use the gate as an
    /// existence oracle
    /// ([`plexus_auth_core_ut1::TenantGate::authorize_read_of`]).
    pub async fn get(&self, id: Uuid) -> Result<Facet, GateError> {
        let facet = match self.store.get_facet(id).await {
            Ok(f) => f,
            Err(StoreError::NotFound(_)) => return Err(GateError::NotFound),
            Err(e) => return Err(GateError::Store(e)),
        };
        self.gate.authorize_read_of(&facet)?;
        Ok(facet)
    }

    /// Update a facet.
    ///
    /// - Returns [`GateError::NotFound`] if the target doesn't exist (so
    ///   "exists, foreign tenant" is the only path that returns `Forbidden`).
    /// - Returns [`GateError::Unauthenticated`] for anonymous callers,
    ///   [`GateError::Forbidden`] for cross-tenant writes
    ///   ([`plexus_auth_core_ut1::TenantGate::authorize_write_of`]).
    /// - **Preserves** the existing facet's `meta.extra["tenant"]` value
    ///   even if the supplied `facet` mutates it. This is the structural fix
    ///   for the "tenant hop via update" attack (threat-model item 4's
    ///   update-preserve half — backend-side data plumbing, per the UT-1
    ///   adapter contract).
    pub async fn update(&self, mut facet: Facet) -> Result<Facet, GateError> {
        let existing = match self.store.get_facet(facet.id).await {
            Ok(f) => f,
            Err(StoreError::NotFound(_)) => return Err(GateError::NotFound),
            Err(e) => return Err(GateError::Store(e)),
        };
        self.gate.authorize_write_of(&existing)?;
        // Preserve the existing tenant assignment regardless of what the
        // caller put in `facet.meta.extra["tenant"]`. The tenant attribute
        // is structural metadata, not a user-editable field.
        match existing.meta.extra.get("tenant").and_then(|v| v.as_str()) {
            Some(t) => {
                facet.meta.extra.insert(
                    "tenant".to_string(),
                    serde_json::Value::String(t.to_string()),
                );
            }
            None => {
                facet.meta.extra.remove("tenant");
            }
        }
        self.store.update_facet(&facet).await?;
        Ok(facet)
    }

    /// Delete a facet.
    ///
    /// Returns [`GateError::NotFound`] for a missing target;
    /// [`GateError::Unauthenticated`] for anonymous callers;
    /// [`GateError::Forbidden`] if the caller cannot write to an existing
    /// foreign-tenant facet.
    pub async fn delete(&self, id: Uuid) -> Result<(), GateError> {
        let existing = match self.store.get_facet(id).await {
            Ok(f) => f,
            Err(StoreError::NotFound(_)) => return Err(GateError::NotFound),
            Err(e) => return Err(GateError::Store(e)),
        };
        self.gate.authorize_write_of(&existing)?;
        self.store.delete_facet(id).await?;
        Ok(())
    }

    /// List children of a parent, filtering out facets the caller cannot see.
    ///
    /// **Performance caveat:** filtering happens after the store query so a
    /// caller still pays the I/O cost of foreign-tenant rows. Push-down
    /// filtering (parameterized `tenant_id` SQL predicate) is tracked under
    /// AUTHZ-DATA-2-MACRO.
    pub async fn list_children(
        &self,
        parent: Option<Uuid>,
    ) -> Result<Vec<Facet>, GateError> {
        let all = self.store.list_children(parent).await?;
        Ok(all.into_iter().filter(|f| self.gate.visible(f)).collect())
    }

    // ─── Read paths (visibility-filtered) ────────────────────────────────

    /// Walk the subtree rooted at `id`, filtering every node by visibility.
    ///
    /// If the root itself is not visible to the caller, returns an empty
    /// vec — this avoids leaking "the root exists but its children are
    /// hidden" via a non-empty-but-empty-after-filter response. The store's
    /// underlying `get_subtree` is allowed to surface
    /// [`StoreError::NotFound`]; we map it to an empty result to match the
    /// existence-oracle defense applied in [`Self::get`].
    pub async fn subtree(&self, id: Uuid) -> Result<Vec<(Facet, u32)>, GateError> {
        // Probe the root via the gate's get — both for visibility and to
        // produce the "no such root" → empty mapping.
        match self.get(id).await {
            Ok(_) => {}
            Err(GateError::NotFound) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        }
        let nodes = self.store.get_subtree(id).await?;
        Ok(nodes
            .into_iter()
            .filter(|(f, _)| self.gate.visible(f))
            .collect())
    }

    /// Full-text search delegating to [`FacetStore::search`], then filtering
    /// matches the caller cannot see.
    ///
    /// As with `list_children`, filtering is post-query; push-down to the
    /// FTS5 join is follow-up work.
    pub async fn search(&self, query: &str) -> Result<Vec<(Facet, f64)>, GateError> {
        let results = self.store.search(query).await?;
        Ok(results
            .into_iter()
            .filter(|(f, _)| self.gate.visible(f))
            .collect())
    }

    /// Collect every facet reachable from the store roots, restricted to
    /// those the caller can see.
    ///
    /// Used by `grep`, which today loads "everything" client-side and runs
    /// the regex match. The result preserves the (root, depth-first
    /// traversal) order that the pre-gate handler relied on so wire output
    /// remains stable when no tenant scoping is in play.
    pub async fn collect_all_visible(&self) -> Result<Vec<Facet>, GateError> {
        let roots = self.store.list_roots().await?;
        let mut all = Vec::new();
        for root in roots {
            if self.gate.visible(&root) {
                let root_id = root.id;
                all.push(root);
                if let Ok(children) = self.store.get_subtree(root_id).await {
                    for (f, _depth) in children {
                        if self.gate.visible(&f) {
                            all.push(f);
                        }
                    }
                }
            }
            // If the root is invisible the entire subtree is skipped
            // conservatively (subtrees mix freely today).
        }
        Ok(all)
    }

    /// List edges connected to `id`, filtering edges whose far-endpoint
    /// (the facet on the other side of `direction`) is invisible to the
    /// caller. Also returns [`GateError::NotFound`] when the focal facet
    /// itself is invisible — see [`Self::get`] for the rationale.
    ///
    /// "Both" semantics: an edge counts as visible iff **both** endpoints
    /// are visible to the caller (a half-visible edge is still a leak —
    /// the caller learns that the invisible endpoint exists and is wired
    /// into the visible graph).
    pub async fn edges(
        &self,
        id: Uuid,
        direction: Direction,
        kind: Option<&EdgeKind>,
    ) -> Result<Vec<Edge>, GateError> {
        // Visibility check on focal facet — also folds in NotFound mapping
        // when the focal facet does not exist.
        let _focal = self.get(id).await?;
        let edges = self.store.get_edges(id, direction, kind).await?;
        let mut keep = Vec::with_capacity(edges.len());
        for edge in edges {
            // Both endpoints must be visible. Fetch the far endpoint.
            let far_id = if edge.from_id == id {
                edge.to_id
            } else {
                edge.from_id
            };
            match self.store.get_facet(far_id).await {
                Ok(far) if self.gate.visible(&far) => keep.push(edge),
                _ => {
                    // Far endpoint missing or invisible — drop the edge.
                }
            }
        }
        Ok(keep)
    }

    /// Blockers helper: for every visible child of `parent`, find dependency
    /// targets whose far-endpoint is visible and not `done`. Returns
    /// `(facet, blocker_ids)` pairs for facets that actually have blockers.
    ///
    /// A blocker that lives in a foreign tenant is treated as "not a
    /// blocker" — from the caller's POV the blocker does not exist
    /// (confirming it would leak schedule signal across the boundary).
    pub async fn blocked_in(
        &self,
        parent: Option<Uuid>,
    ) -> Result<Vec<(Facet, Vec<Uuid>)>, GateError> {
        let facets = self.list_children(parent).await?;
        let mut report = Vec::new();
        for facet in facets {
            let deps = match self
                .store
                .get_edges(facet.id, Direction::Outgoing, Some(&EdgeKind::DependsOn))
                .await
            {
                Ok(d) => d,
                Err(_) => continue,
            };
            let mut blockers = Vec::new();
            for dep in &deps {
                match self.store.get_facet(dep.to_id).await {
                    Ok(target) if self.gate.visible(&target) && target.status != "done" => {
                        blockers.push(dep.to_id);
                    }
                    _ => {
                        // Target missing or invisible — not a blocker for
                        // this caller.
                    }
                }
            }
            if !blockers.is_empty() {
                report.push((facet, blockers));
            }
        }
        Ok(report)
    }

    // ─── Write paths (auth-required, write-predicate enforced) ───────────

    /// Add an edge between `from` and `to`. Requires the caller to have
    /// write access to BOTH endpoints. Anonymous callers receive
    /// [`GateError::Unauthenticated`] before any store I/O; cross-tenant
    /// endpoints yield [`GateError::Forbidden`] (write paths already
    /// concede existence via the corresponding `create` calls).
    pub async fn add_edge(&self, edge: Edge) -> Result<Edge, GateError> {
        if self.gate.is_anonymous() {
            return Err(GateError::Unauthenticated);
        }
        let from = self.store.get_facet(edge.from_id).await?;
        let to = self.store.get_facet(edge.to_id).await?;
        self.gate.authorize_write_of(&from)?;
        self.gate.authorize_write_of(&to)?;
        self.store.add_edge(&edge).await?;
        Ok(edge)
    }

    /// Remove an edge between `from` and `to`. Same write-predicate as
    /// [`Self::add_edge`].
    pub async fn remove_edge(
        &self,
        from_id: Uuid,
        to_id: Uuid,
        kind: &EdgeKind,
    ) -> Result<(), GateError> {
        if self.gate.is_anonymous() {
            return Err(GateError::Unauthenticated);
        }
        let from = self.store.get_facet(from_id).await?;
        let to = self.store.get_facet(to_id).await?;
        self.gate.authorize_write_of(&from)?;
        self.gate.authorize_write_of(&to)?;
        self.store.remove_edge(from_id, to_id, kind).await?;
        Ok(())
    }

    /// Move a facet to a new parent (or to root if `new_parent` is `None`).
    ///
    /// - Caller must write to the source facet.
    /// - If `new_parent` is `Some(p)`, the caller must also write to `p`.
    /// - Root-move (`None`) is allowed for any caller who can write to the
    ///   source — a "public root" is a no-tenant facet and is freely
    ///   addressable.
    /// - Returns the source's old parent on success (for event emission).
    pub async fn move_to(
        &self,
        id: Uuid,
        new_parent: Option<Uuid>,
    ) -> Result<Option<Uuid>, GateError> {
        if self.gate.is_anonymous() {
            return Err(GateError::Unauthenticated);
        }
        let source = match self.store.get_facet(id).await {
            Ok(f) => f,
            Err(StoreError::NotFound(_)) => return Err(GateError::NotFound),
            Err(e) => return Err(GateError::Store(e)),
        };
        self.gate.authorize_write_of(&source)?;
        if let Some(parent_id) = new_parent {
            let parent = match self.store.get_facet(parent_id).await {
                Ok(f) => f,
                Err(StoreError::NotFound(_)) => return Err(GateError::NotFound),
                Err(e) => return Err(GateError::Store(e)),
            };
            self.gate.authorize_write_of(&parent)?;
        }
        let old_parent = source.parent_id;
        self.store.move_facet(id, new_parent).await?;
        Ok(old_parent)
    }
}

#[cfg(test)]
mod tests {
    //! In-module sanity tests for the gate predicates (now delegated to the
    //! generalized `plexus_auth_core_ut1::TenantGate`). End-to-end pentest
    //! coverage lives in `tests/tenant_isolation_test.rs`.

    use super::*;
    use crate::types::FacetMeta;
    use chrono::Utc;
    use serde_json::{json, Value};

    /// Compose an `AuthContext` carrying an `org_id` claim — what the
    /// UT-W3 OIDC validator emits in production (it also writes the
    /// `tenant_id` deprecation alias; the resolver reads either).
    fn ctx_with_tenant(user: &str, tenant: &str) -> AuthContext {
        AuthContext::new(
            user.to_string(),
            "sess-1".to_string(),
            vec![],
            json!({"org_id": tenant}),
        )
    }

    /// Legacy-claim context: only `tenant_id` (the pre-cutover shape).
    /// Pinned to keep resolving during the UT-S01 D3 deprecation window.
    fn ctx_with_legacy_tenant(user: &str, tenant: &str) -> AuthContext {
        AuthContext::new(
            user.to_string(),
            "sess-1".to_string(),
            vec![],
            json!({"tenant_id": tenant}),
        )
    }

    /// Empty session_id is the canonical "not authenticated" signal per
    /// `AuthContext::is_authenticated`. The generalized gate rejects this
    /// shape even when a tenancy claim is present.
    fn ctx_forged(user: &str, tenant: &str) -> AuthContext {
        AuthContext::new(
            user.to_string(),
            String::new(), // empty session → !is_authenticated
            vec![],
            json!({"org_id": tenant}),
        )
    }

    /// Build a facet with the given tenant tag in meta.extra.
    fn facet_in_tenant(tenant: Option<&str>) -> Facet {
        let mut meta = FacetMeta::default();
        if let Some(t) = tenant {
            meta.extra
                .insert("tenant".to_string(), Value::String(t.to_string()));
        }
        let now = Utc::now();
        Facet {
            id: Uuid::new_v4(),
            parent_id: None,
            title: "test".to_string(),
            body: None,
            status: "open".to_string(),
            owner: "anyone".to_string(),
            meta,
            created_at: now,
            updated_at: now,
        }
    }

    /// Standalone predicate tests do not need a real store; the predicate
    /// methods never touch it, so a panicking stub suffices.
    #[derive(Default)]
    struct NoopStore;

    #[async_trait::async_trait]
    impl FacetStore for NoopStore {
        async fn create_facet(&self, _: &Facet) -> Result<(), StoreError> {
            unimplemented!()
        }
        async fn get_facet(&self, _: Uuid) -> Result<Facet, StoreError> {
            unimplemented!()
        }
        async fn update_facet(&self, _: &Facet) -> Result<(), StoreError> {
            unimplemented!()
        }
        async fn delete_facet(&self, _: Uuid) -> Result<(), StoreError> {
            unimplemented!()
        }
        async fn move_facet(
            &self,
            _: Uuid,
            _: Option<Uuid>,
        ) -> Result<(), StoreError> {
            unimplemented!()
        }
        async fn list_children(
            &self,
            _: Option<Uuid>,
        ) -> Result<Vec<Facet>, StoreError> {
            unimplemented!()
        }
        async fn list_roots(&self) -> Result<Vec<Facet>, StoreError> {
            unimplemented!()
        }
        async fn get_ancestors(&self, _: Uuid) -> Result<Vec<Facet>, StoreError> {
            unimplemented!()
        }
        async fn get_subtree(
            &self,
            _: Uuid,
        ) -> Result<Vec<(Facet, u32)>, StoreError> {
            unimplemented!()
        }
        async fn count_children(
            &self,
            _: Option<Uuid>,
        ) -> Result<u32, StoreError> {
            unimplemented!()
        }
        async fn add_edge(&self, _: &crate::types::Edge) -> Result<(), StoreError> {
            unimplemented!()
        }
        async fn remove_edge(
            &self,
            _: Uuid,
            _: Uuid,
            _: &crate::types::EdgeKind,
        ) -> Result<(), StoreError> {
            unimplemented!()
        }
        async fn get_edges(
            &self,
            _: Uuid,
            _: crate::store::Direction,
            _: Option<&crate::types::EdgeKind>,
        ) -> Result<Vec<crate::types::Edge>, StoreError> {
            unimplemented!()
        }
        async fn search(&self, _: &str) -> Result<Vec<(Facet, f64)>, StoreError> {
            unimplemented!()
        }
    }

    fn noop() -> Arc<dyn FacetStore> {
        Arc::new(NoopStore)
    }

    #[tokio::test]
    async fn anonymous_caller_sees_only_public_facets() {
        let gate = TenantGate::from_auth(noop(), None).await;
        assert!(gate.can_see(&facet_in_tenant(None)));
        assert!(!gate.can_see(&facet_in_tenant(Some("acme"))));
    }

    #[tokio::test]
    async fn tenant_caller_sees_own_and_public() {
        let ctx = ctx_with_tenant("alice", "acme");
        let gate = TenantGate::from_auth(noop(), Some(&ctx)).await;
        assert!(gate.can_see(&facet_in_tenant(None)));
        assert!(gate.can_see(&facet_in_tenant(Some("acme"))));
        assert!(!gate.can_see(&facet_in_tenant(Some("neon"))));
    }

    #[tokio::test]
    async fn legacy_tenant_id_claim_still_resolves() {
        // UT-S01 D3 deprecation window: contexts carrying only the legacy
        // `tenant_id` key (pre-cutover validators) keep resolving.
        let ctx = ctx_with_legacy_tenant("alice", "acme");
        let gate = TenantGate::from_auth(noop(), Some(&ctx)).await;
        assert_eq!(gate.caller_tenant().map(|t| t.as_str()), Some("acme"));
    }

    #[tokio::test]
    async fn anonymous_cannot_write_anything() {
        let gate = TenantGate::from_auth(noop(), None).await;
        assert!(!gate.can_write(&facet_in_tenant(None)));
        assert!(!gate.can_write(&facet_in_tenant(Some("acme"))));
    }

    #[tokio::test]
    async fn tenant_writes_own_and_public_only() {
        let ctx = ctx_with_tenant("alice", "acme");
        let gate = TenantGate::from_auth(noop(), Some(&ctx)).await;
        assert!(gate.can_write(&facet_in_tenant(None)));
        assert!(gate.can_write(&facet_in_tenant(Some("acme"))));
        assert!(!gate.can_write(&facet_in_tenant(Some("neon"))));
    }

    #[tokio::test]
    async fn forged_unauthenticated_context_resolves_to_anonymous() {
        // No claim + empty session_id → gate is anonymous.
        let ctx = AuthContext::new(
            "alice".into(),
            String::new(), // empty session
            vec![],
            json!({}), // no tenant claim
        );
        let gate = TenantGate::from_auth(noop(), Some(&ctx)).await;
        assert!(gate.caller_tenant().is_none());
    }

    #[tokio::test]
    async fn forged_ctx_with_claim_but_no_session_is_rejected_by_gate() {
        // org_id claim present, but empty session_id. The generalized
        // gate's from_auth rejects any AuthContext where
        // `is_authenticated() == false` — the layered defense the trak
        // reference pinned and UT-1 extracted verbatim.
        let ctx = ctx_forged("alice", "acme");
        let gate = TenantGate::from_auth(noop(), Some(&ctx)).await;
        assert!(
            gate.caller_tenant().is_none(),
            "gate must reject unauthenticated AuthContext even if it carries a tenancy claim"
        );
    }

    #[tokio::test]
    async fn corrupt_tenant_tag_is_not_public() {
        // A stored tag that fails TenantId validation must NOT collapse to
        // "public" (per the TenantTagged contract) — it maps to the
        // sentinel, which no caller's resolved tenant can equal.
        let mut meta = FacetMeta::default();
        meta.extra.insert(
            "tenant".to_string(),
            Value::String("evil\u{0000}tenant".to_string()),
        );
        let now = Utc::now();
        let corrupt = Facet {
            id: Uuid::new_v4(),
            parent_id: None,
            title: "corrupt".to_string(),
            body: None,
            status: "open".to_string(),
            owner: "anyone".to_string(),
            meta,
            created_at: now,
            updated_at: now,
        };

        let anon = TenantGate::from_auth(noop(), None).await;
        assert!(!anon.can_see(&corrupt), "corrupt tag must not become public");

        let ctx = ctx_with_tenant("alice", "acme");
        let gate = TenantGate::from_auth(noop(), Some(&ctx)).await;
        assert!(!gate.can_see(&corrupt));
        assert!(!gate.can_write(&corrupt));
    }
}
