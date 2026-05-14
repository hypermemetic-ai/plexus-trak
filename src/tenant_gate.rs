//! `TenantGate` — handler-side tenant-isolation wrapper around `FacetStore`.
//!
//! This is a **trak-local** demonstration of multi-tenant isolation built on
//! the *usable* primitives now exported by `plexus-auth-core`:
//!
//! - [`plexus_auth_core::Tenant`] — sealed unit of data isolation. Its
//!   constructor is crate-private; the only path to a `Tenant` value is via
//!   the framework's `TenantResolver`.
//! - [`plexus_auth_core::ClaimTenantResolver`] — reads `tenant_id` from the
//!   verified `AuthContext` metadata and (with `single_user_fallback = true`)
//!   falls back to the user id for single-user deployments.
//!
//! # Why not `Tenanted<S>` / `Scoped<'_, S>`?
//!
//! Wave 1+2 of AUTHZ landed `Tenanted<S>` and `Scoped<'_, S>` in
//! `plexus-auth-core::tenant::storage`, but the `TenantScopedStore` trait is
//! sealed and `Tenanted::new_sealed` is `pub(crate)` — a third crate cannot
//! wrap its own store in `Tenanted`. That gap is tracked by
//! `AUTHZ-DATA-2-MACRO` (Pending). Until that ticket lands, downstream crates
//! that need tenant isolation today must roll a handler-side gate (this
//! module). The gate is intentionally NOT introduced as a new public API in
//! `plexus-auth-core`; it lives in trak.
//!
//! # Threat model
//!
//! The gate sits **after** session validation (so `AuthContext` is always
//! trustworthy at this layer — forging it is outside the trust boundary) and
//! **before** the store. It defends:
//!
//! 1. **Cross-tenant reads** — tenant B asking for tenant A's facet by UUID
//!    must receive `NotFound` (not `Forbidden`) to avoid an existence-oracle
//!    leak.
//! 2. **Cross-tenant writes** — tenant B updating / deleting tenant A's
//!    facet must receive `Forbidden`. Existence is already exposed by the
//!    create path, so write-side denials use the more honest signal.
//! 3. **Cross-tenant listing** — `list_children` post-filters the store's
//!    result vec so a caller never sees a foreign-tenant facet in the
//!    output. (Inefficient for tenant-private datasets; correct for the
//!    demo. Push-down filtering is a follow-up.)
//! 4. **Tenant hopping via metadata** — a caller cannot move a facet to
//!    another tenant by setting `meta_extra.tenant = "B"`. On create, the
//!    caller's resolved tenant overwrites any forged value; on update, the
//!    existing tenant value is preserved verbatim.
//! 5. **Anonymous writes** — `create`, `update`, `delete` always return
//!    `Unauthenticated` for callers with no resolved tenant.
//! 6. **Forged `AuthContext`** — an `AuthContext` carrying a `tenant_id`
//!    claim but no valid session (`is_authenticated() == false`, e.g.
//!    empty `session_id`) is rejected by `ClaimTenantResolver` and the
//!    gate treats the caller as anonymous.
//!
//! Each item is verified by a test in `tests/tenant_isolation_test.rs`.

use std::sync::Arc;

// `AuthContext` is re-exported by `plexus-core` from `plexus-auth-core`
// (AUTHZ-CORE-CRATE-1). Importing directly from `plexus_auth_core` here
// makes the resolver primitive's signature line up without any field
// mirroring; `plexus_core::plexus::AuthContext` is the same type.
use plexus_auth_core::{AuthContext, ClaimTenantResolver, Tenant, TenantResolver};
use uuid::Uuid;

use crate::store::{Direction, FacetStore, StoreError};
use crate::types::{Edge, EdgeKind, Facet};

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

/// Tenant-isolating wrapper around a [`FacetStore`].
///
/// One `TenantGate` is constructed per request via [`TenantGate::from_auth`].
/// It holds:
///
/// - The shared `Arc<dyn FacetStore>` (no per-request allocation).
/// - The caller's resolved [`Tenant`], or `None` if the caller is anonymous
///   or could not be resolved.
///
/// All accessors enforce the visibility / write predicates documented at the
/// module level.
pub struct TenantGate {
    store: Arc<dyn FacetStore>,
    tenant: Option<Tenant>,
}

impl TenantGate {
    /// Build a gate for the given store and (optional) caller context.
    ///
    /// Resolution flow:
    ///
    /// 1. If `auth` is `None`, the gate has `tenant = None` (anonymous).
    /// 2. Otherwise, the `AuthContext` is passed to
    ///    [`ClaimTenantResolver::new`] (claim key `"tenant_id"`,
    ///    `single_user_fallback = true`).
    /// 3. On resolver success → `tenant = Some(...)`.
    /// 4. On resolver error (anonymous, missing claim, malformed) →
    ///    `tenant = None`.
    ///
    /// Post-AUTHZ-CORE-CRATE-1 the `plexus_core::plexus::AuthContext` used
    /// by trak handlers is the **same type** as the
    /// `plexus_auth_core::AuthContext` the resolver consumes (it's a
    /// re-export). No field mirroring is required.
    pub async fn from_auth(
        store: Arc<dyn FacetStore>,
        auth: Option<&AuthContext>,
    ) -> Self {
        let tenant = match auth {
            None => None,
            Some(ctx) => {
                // Defense in depth: ClaimTenantResolver does NOT itself
                // check `is_authenticated()` when a claim is present (the
                // resolver trusts the AuthContext post-SessionValidator).
                // The gate adds a belt-and-suspenders check so a caller
                // who hand-crafts an AuthContext with a tenant_id claim
                // but an empty session_id still resolves to anonymous.
                // The `forged_authcontext_does_not_grant_tenant` pentest
                // pins this layered defense.
                if !ctx.is_authenticated() {
                    None
                } else {
                    let resolver = ClaimTenantResolver::new();
                    resolver.resolve(ctx).await.ok()
                }
            }
        };
        Self { store, tenant }
    }

    /// The caller's resolved tenant, if any. `None` ↔ anonymous.
    pub fn caller_tenant(&self) -> Option<&Tenant> {
        self.tenant.as_ref()
    }

    /// Read the tenant attribute stored on a facet (in `meta.extra["tenant"]`).
    ///
    /// Tenancy is currently encoded in the facet's metadata bag rather than a
    /// dedicated column. This helper centralizes the lookup so it stays one
    /// line to change when AUTHZ-DATA-2-MACRO adds proper `tenant_id`
    /// scoping at the store layer.
    fn facet_tenant_str(facet: &Facet) -> Option<&str> {
        facet.meta.extra.get("tenant").and_then(|v| v.as_str())
    }

    /// Visibility predicate: can the caller see this facet?
    ///
    /// | caller     | facet.tenant   | result |
    /// |------------|----------------|--------|
    /// | `None`     | `None`         | `true` (anonymous sees public) |
    /// | `None`     | `Some(_)`      | `false` (anonymous cannot see tenant-owned) |
    /// | `Some(t)`  | `None`         | `true` (tenant sees public) |
    /// | `Some(t)`  | `Some(ft)`     | `t.as_str() == ft` |
    pub fn can_see(&self, facet: &Facet) -> bool {
        match (self.tenant.as_ref(), Self::facet_tenant_str(facet)) {
            (None, None) => true,
            (None, Some(_)) => false,
            (Some(_), None) => true,
            (Some(t), Some(ft)) => t.as_str() == ft,
        }
    }

    /// Write predicate: can the caller mutate this facet?
    ///
    /// Writes always require an authenticated tenant. A tenant can mutate
    /// public (untenanted) facets and facets in its own tenant.
    pub fn can_write(&self, facet: &Facet) -> bool {
        match (self.tenant.as_ref(), Self::facet_tenant_str(facet)) {
            (None, _) => false,
            (Some(_), None) => true,
            (Some(t), Some(ft)) => t.as_str() == ft,
        }
    }

    // ─── Store-mirror methods (visibility-enforced) ──────────────────────

    /// Create a facet on behalf of the caller.
    ///
    /// - Requires an authenticated caller (`tenant.is_some()`); anonymous
    ///   callers receive [`GateError::Unauthenticated`].
    /// - **Forces** `facet.meta.extra["tenant"]` to the caller's resolved
    ///   tenant, **overwriting** any forged value the caller may have
    ///   tried to set. This is the structural fix for the "tenant hop via
    ///   create metadata" attack.
    pub async fn create(&self, mut facet: Facet) -> Result<Facet, GateError> {
        let Some(t) = self.tenant.as_ref() else {
            return Err(GateError::Unauthenticated);
        };
        // Caller's resolved tenant wins. Any caller-supplied `tenant` value
        // in meta_extra is discarded — overwriting is intentional, see the
        // `tenant_cannot_hop_via_create_metadata_override` pentest.
        facet.meta.extra.insert(
            "tenant".to_string(),
            serde_json::Value::String(t.as_str().to_string()),
        );
        self.store.create_facet(&facet).await?;
        Ok(facet)
    }

    /// Get a facet by UUID.
    ///
    /// Returns [`GateError::NotFound`] when the facet does not exist OR when
    /// the caller cannot see it. The two cases are indistinguishable to the
    /// caller by design — a foreign-tenant probe cannot use the gate as an
    /// existence oracle.
    pub async fn get(&self, id: Uuid) -> Result<Facet, GateError> {
        let facet = match self.store.get_facet(id).await {
            Ok(f) => f,
            Err(StoreError::NotFound(_)) => return Err(GateError::NotFound),
            Err(e) => return Err(GateError::Store(e)),
        };
        if !self.can_see(&facet) {
            return Err(GateError::NotFound);
        }
        Ok(facet)
    }

    /// Update a facet.
    ///
    /// - Returns [`GateError::NotFound`] if the target doesn't exist (the
    ///   underlying not-found is the same for write paths; we surface
    ///   `NotFound` rather than `Forbidden` for the not-exists case so
    ///   "exists, foreign tenant" is the only path that returns `Forbidden`).
    /// - Returns [`GateError::Forbidden`] if the caller cannot write.
    /// - **Preserves** the existing facet's `meta.extra["tenant"]` value
    ///   even if the supplied `facet` mutates it. This is the structural fix
    ///   for the "tenant hop via update" attack.
    pub async fn update(&self, mut facet: Facet) -> Result<Facet, GateError> {
        let existing = match self.store.get_facet(facet.id).await {
            Ok(f) => f,
            Err(StoreError::NotFound(_)) => return Err(GateError::NotFound),
            Err(e) => return Err(GateError::Store(e)),
        };
        if !self.can_write(&existing) {
            return Err(GateError::Forbidden);
        }
        // Preserve the existing tenant assignment regardless of what the
        // caller put in `facet.meta.extra["tenant"]`. The tenant attribute
        // is structural metadata, not a user-editable field.
        match Self::facet_tenant_str(&existing) {
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
    /// Returns [`GateError::NotFound`] for a missing target; returns
    /// [`GateError::Forbidden`] if the caller cannot write to an existing
    /// foreign-tenant facet.
    pub async fn delete(&self, id: Uuid) -> Result<(), GateError> {
        let existing = match self.store.get_facet(id).await {
            Ok(f) => f,
            Err(StoreError::NotFound(_)) => return Err(GateError::NotFound),
            Err(e) => return Err(GateError::Store(e)),
        };
        if !self.can_write(&existing) {
            return Err(GateError::Forbidden);
        }
        self.store.delete_facet(id).await?;
        Ok(())
    }

    /// List children of a parent, filtering out facets the caller cannot see.
    ///
    /// **Performance caveat:** filtering happens after the store query so a
    /// caller still pays the I/O cost of foreign-tenant rows. Acceptable for
    /// the demo; a real impl needs push-down filtering (parameterized
    /// `tenant_id` SQL predicate). Tracked under AUTHZ-DATA-2-MACRO.
    pub async fn list_children(
        &self,
        parent: Option<Uuid>,
    ) -> Result<Vec<Facet>, GateError> {
        let all = self.store.list_children(parent).await?;
        Ok(all.into_iter().filter(|f| self.can_see(f)).collect())
    }

    // ─── Read paths (visibility-filtered) ────────────────────────────────

    /// Walk the subtree rooted at `id`, filtering every node by `can_see`.
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
            .filter(|(f, _)| self.can_see(f))
            .collect())
    }

    /// Full-text search delegating to [`FacetStore::search`], then filtering
    /// matches the caller cannot see.
    ///
    /// As with `list_children`, filtering is post-query for the demo;
    /// push-down to the FTS5 join is follow-up work.
    pub async fn search(&self, query: &str) -> Result<Vec<(Facet, f64)>, GateError> {
        let results = self.store.search(query).await?;
        Ok(results
            .into_iter()
            .filter(|(f, _)| self.can_see(f))
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
            if self.can_see(&root) {
                let root_id = root.id;
                all.push(root);
                if let Ok(children) = self.store.get_subtree(root_id).await {
                    for (f, _depth) in children {
                        if self.can_see(&f) {
                            all.push(f);
                        }
                    }
                }
            }
            // If the root is invisible the entire subtree is invisible
            // too (a child of an invisible root cannot have a visible
            // tenant tag and remain reachable to a foreign tenant —
            // currently subtrees mix freely, so we conservatively skip).
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
            // Implementation note: the focal endpoint is already visible
            // (we just fetched it), but we still re-check `can_see` on the
            // far facet via the gate to keep the rule symmetrical.
            let far_id = if edge.from_id == id {
                edge.to_id
            } else {
                edge.from_id
            };
            match self.store.get_facet(far_id).await {
                Ok(far) if self.can_see(&far) => keep.push(edge),
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
    /// This is purpose-built for the `blocked` handler — keeping the join
    /// logic alongside the gate so the foreign-tenant filter is enforced
    /// uniformly. A blocker that lives in a foreign tenant is treated as
    /// "not a blocker" — but it's also not surfaced via this listing,
    /// which is the correct behavior: from the caller's POV the blocker
    /// does not exist.
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
                    Ok(target) if self.can_see(&target) && target.status != "done" => {
                        blockers.push(dep.to_id);
                    }
                    _ => {
                        // Target missing or invisible — not a blocker for
                        // this caller. Cross-tenant blockers are also
                        // hidden, even when they exist and are non-done,
                        // because confirming their existence would leak
                        // schedule signal across the tenant boundary.
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
    /// write access to BOTH endpoints. Returns `Forbidden` (not
    /// `NotFound`) when either endpoint is foreign — write paths already
    /// concede existence via the corresponding `create` calls.
    pub async fn add_edge(&self, edge: Edge) -> Result<Edge, GateError> {
        if self.tenant.is_none() {
            return Err(GateError::Unauthenticated);
        }
        let from = self.store.get_facet(edge.from_id).await?;
        let to = self.store.get_facet(edge.to_id).await?;
        if !self.can_write(&from) || !self.can_write(&to) {
            return Err(GateError::Forbidden);
        }
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
        if self.tenant.is_none() {
            return Err(GateError::Unauthenticated);
        }
        let from = self.store.get_facet(from_id).await?;
        let to = self.store.get_facet(to_id).await?;
        if !self.can_write(&from) || !self.can_write(&to) {
            return Err(GateError::Forbidden);
        }
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
        if self.tenant.is_none() {
            return Err(GateError::Unauthenticated);
        }
        let source = match self.store.get_facet(id).await {
            Ok(f) => f,
            Err(StoreError::NotFound(_)) => return Err(GateError::NotFound),
            Err(e) => return Err(GateError::Store(e)),
        };
        if !self.can_write(&source) {
            return Err(GateError::Forbidden);
        }
        if let Some(parent_id) = new_parent {
            let parent = match self.store.get_facet(parent_id).await {
                Ok(f) => f,
                Err(StoreError::NotFound(_)) => return Err(GateError::NotFound),
                Err(e) => return Err(GateError::Store(e)),
            };
            if !self.can_write(&parent) {
                return Err(GateError::Forbidden);
            }
        }
        let old_parent = source.parent_id;
        self.store.move_facet(id, new_parent).await?;
        Ok(old_parent)
    }
}

#[cfg(test)]
mod tests {
    //! In-module sanity tests for the gate predicates. End-to-end pentest
    //! coverage lives in `tests/tenant_isolation_test.rs`.

    use super::*;
    use crate::types::FacetMeta;
    use chrono::Utc;
    use serde_json::{json, Value};

    /// Compose an `AuthContext` carrying a `tenant_id` claim. Helper for
    /// pentest setup; mirrors what the JWT validator emits in production.
    fn ctx_with_tenant(user: &str, tenant: &str) -> AuthContext {
        AuthContext::new(
            user.to_string(),
            "sess-1".to_string(),
            vec![],
            json!({"tenant_id": tenant}),
        )
    }

    /// Empty session_id is the canonical "not authenticated" signal per
    /// `AuthContext::is_authenticated`. The resolver's
    /// `single_user_fallback` branch is gated on `is_authenticated()`, so
    /// this shape resolves to None even though the claim is present.
    fn ctx_forged(user: &str, tenant: &str) -> AuthContext {
        AuthContext::new(
            user.to_string(),
            String::new(), // empty session → !is_authenticated
            vec![],
            json!({"tenant_id": tenant}),
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

    /// Standalone predicate tests do not need a real store; we use a Null
    /// store stand-in by going through the constructor's tenant-only path
    /// with a no-op store. Because the predicate methods do not touch the
    /// store, we can use a stub.
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
        // No claim + empty session_id → gate.tenant = None.
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
        // tenant_id claim present, but empty session_id.
        //
        // FINDING: ClaimTenantResolver itself does NOT check
        // is_authenticated() before honoring a tenant_id claim — it trusts
        // the AuthContext as post-SessionValidator. That leaves a gap when
        // an upstream layer (or a test) constructs an AuthContext directly
        // without going through the validator.
        //
        // The gate closes the gap as defense-in-depth: `from_auth` rejects
        // any AuthContext where `is_authenticated() == false`. Even if a
        // caller fabricates `{"tenant_id": "acme"}` with empty session_id,
        // the gate treats them as anonymous.
        let ctx = ctx_forged("alice", "acme");
        let gate = TenantGate::from_auth(noop(), Some(&ctx)).await;
        assert!(
            gate.caller_tenant().is_none(),
            "gate must reject unauthenticated AuthContext even if it carries a tenant_id claim"
        );
    }
}
