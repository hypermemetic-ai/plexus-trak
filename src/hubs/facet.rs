use std::sync::Arc;

use async_stream::stream;
use futures::Stream;
use plexus_core::plexus::AuthContext;

use crate::events::TrakEvent;
use crate::store::{Direction, FacetStore, StoreError};
use crate::tenant_gate::{GateError, TenantGate};
use crate::types::{Edge, EdgeKind, Facet, FacetUpdate, NewFacet};

/// Post-filter a slice of facets by tag/priority criteria.
///
/// Filtering is in-memory after the store query because:
/// 1. Tags live in a JSON column (`meta_json`), not a normalized table.
///    SQLite JSON1 (`json_extract(meta_json, '$.tags')`) would work but
///    requires per-call SQL composition; the per-row deserialize cost is
///    already paid by `row_to_facet`, so post-filter is O(n) over the
///    already-loaded set.
/// 2. The acceptance criterion targets a 1000-facet dataset under 100ms;
///    in-memory filter on a Vec<Facet> easily clears that.
///
/// Semantics (from TRAK-API-3):
/// - `tags_any` non-empty → keep facets whose meta.tags overlaps (OR).
/// - `tags_all` non-empty → keep facets whose meta.tags is a superset (AND).
/// - `priority` non-empty → keep facets whose meta.priority ∈ values.
/// - All three combine with AND across categories.
/// - Any empty/None filter is a no-op.
pub fn filter_facets(
    facets: Vec<Facet>,
    tags_any: Option<&[String]>,
    tags_all: Option<&[String]>,
    priority: Option<&[String]>,
) -> Vec<Facet> {
    let tags_any = tags_any.filter(|t| !t.is_empty());
    let tags_all = tags_all.filter(|t| !t.is_empty());
    let priority = priority.filter(|p| !p.is_empty());

    if tags_any.is_none() && tags_all.is_none() && priority.is_none() {
        return facets;
    }

    facets
        .into_iter()
        .filter(|f| {
            let facet_tags: &[String] = f.meta.tags.as_deref().unwrap_or(&[]);

            if let Some(any) = tags_any {
                // OR semantics: at least one of `any` is in facet_tags.
                if !any.iter().any(|t| facet_tags.contains(t)) {
                    return false;
                }
            }
            if let Some(all) = tags_all {
                // AND semantics: every tag in `all` is in facet_tags.
                if !all.iter().all(|t| facet_tags.contains(t)) {
                    return false;
                }
            }
            if let Some(prios) = priority {
                match &f.meta.priority {
                    Some(p) if prios.iter().any(|x| x == p) => {}
                    _ => return false,
                }
            }
            true
        })
        .collect()
}

/// FacetHub — core CRUD + tree + link operations on facets.
#[derive(Clone)]
pub struct FacetHub {
    store: Arc<dyn FacetStore>,
}

impl FacetHub {
    pub fn new(store: Arc<dyn FacetStore>) -> Self {
        Self { store }
    }
}

/// Extract the owner string from an auth context.
fn owner_from_auth(auth: &AuthContext) -> String {
    auth.get_metadata_string("username")
        .unwrap_or_else(|| auth.user_id.clone())
}

/// Extract the tenant from an auth context (if any).
fn tenant_from_auth(auth: &AuthContext) -> Option<String> {
    auth.tenant()
}

#[plexus_macros::activation(
    namespace = "facet",
    version = "0.1.0",
    description = "Facet CRUD, tree traversal, linking, and search",
    auth_posture = "mixed"
)]
impl FacetHub {
    /// Create a new facet
    ///
    /// Wire-level params remain flat for backward compat (--title, --body,
    /// --parent-id, --status). New optional params (--tags, --priority,
    /// --meta-extra) flow through to the matching `NewFacet` fields. The
    /// activation builds a `NewFacet` internally and materializes a `Facet`
    /// via `NewFacet::into_facet`. This is the "fallback" path described in
    /// TRAK-API-2 risks — it satisfies the ticket contract while keeping CLI
    /// callers unchanged.
    #[plexus_macros::method(
        description = "Create a new facet (task / epic / note / anything). If authenticated, sets owner from auth context.",
        params(
            title = "Facet title (required, non-empty)",
            body = "Optional body / description",
            parent_id = "Parent facet UUID (omit for root)",
            status = "Initial status (default: open)",
            tags = "Optional list of tags",
            priority = "Optional priority string (e.g. low, medium, high, critical)",
            meta_extra = "Optional JSON object merged into facet.meta extensible bag"
        )
    )]
    async fn create(
        &self,
        auth: &AuthContext,
        title: String,
        body: Option<String>,
        parent_id: Option<String>,
        status: Option<String>,
        tags: Option<Vec<String>>,
        priority: Option<String>,
        meta_extra: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        // Build the tenant gate up front (the resolver is async, and the
        // returned stream is 'static so it can't borrow `auth`). The gate
        // owns its `Tenant` value; the stream captures the gate by move.
        let gate = TenantGate::from_auth(self.store.clone(), Some(auth)).await;
        let owner = owner_from_auth(auth);
        // For the seed `tenant` carried by NewFacet::into_facet we still
        // pass the AuthContext-derived value — but the gate's `create` will
        // override `meta.extra["tenant"]` to the resolved tenant before
        // writing. The "tenant" string here is therefore advisory; the
        // structural truth lives in the gate.
        let tenant = tenant_from_auth(auth);
        stream! {
            let parent_uuid = match parent_id.as_deref().map(uuid::Uuid::parse_str).transpose() {
                Ok(v) => v,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_parent_id".into()), message: e.to_string() };
                    return;
                }
            };
            let new_facet = NewFacet {
                title,
                body,
                parent_id: parent_uuid,
                status,
                tags,
                priority,
                meta_extra,
            };
            if let Err(e) = new_facet.validate() {
                yield TrakEvent::Error { code: Some("invalid_input".into()), message: e };
                return;
            }
            let facet = new_facet.into_facet(owner, tenant);
            match gate.create(facet).await {
                Ok(facet) => yield TrakEvent::FacetCreated { facet },
                Err(GateError::Unauthenticated) => yield TrakEvent::Error {
                    code: Some("unauthenticated".into()),
                    message: "create requires an authenticated tenant".into(),
                },
                Err(e) => yield TrakEvent::Error { code: Some("create_failed".into()), message: e.to_string() },
            }
        }
    }

    /// Get a facet by ID
    ///
    /// **AUTHZ-TENANT-GATE note:** routed through `TenantGate::get`, which
    /// returns `NotFound` for both "does not exist" and "exists but in
    /// foreign tenant". The conflation is intentional (existence-oracle
    /// defense). Ideally this handler would accept `auth: Option<&AuthContext>`
    /// so anonymous callers could still read public facets; the
    /// `plexus-macros::method` codegen unwraps `Option<&AuthContext>` to
    /// `&AuthContext` regardless of the declared shape (see RUN-NOTES under
    /// "macro doesn't support optional auth"). Until that is fixed,
    /// `get` is forced-auth here.
    #[plexus_macros::method(
        description = "Retrieve a single facet by UUID (visibility scoped to caller's tenant)",
        params(id = "Facet UUID")
    )]
    async fn get(
        &self,
        auth: &AuthContext,
        id: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let gate = TenantGate::from_auth(self.store.clone(), Some(auth)).await;
        stream! {
            let uuid = match uuid::Uuid::parse_str(&id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_id".into()), message: e.to_string() };
                    return;
                }
            };
            match gate.get(uuid).await {
                Ok(facet) => yield TrakEvent::FacetDetail { facet },
                Err(GateError::NotFound) => yield TrakEvent::Error { code: Some("not_found".into()), message: format!("facet {id} not found") },
                Err(e) => yield TrakEvent::Error { code: Some("get_failed".into()), message: e.to_string() },
            }
        }
    }

    /// Update a facet
    ///
    /// Wire-level params remain flat; activation builds a `FacetUpdate`
    /// internally and applies it via `FacetUpdate::apply` so all merge
    /// semantics (tags replace; meta_extra shallow-merge with null-deletes)
    /// live in one tested place.
    #[plexus_macros::method(
        description = "Update a facet. Omit a field to leave it unchanged. tags=[] clears tags; meta_extra is shallow-merged (null value deletes a key).",
        params(
            id = "Facet UUID",
            title = "New title (optional)",
            body = "New body (optional)",
            status = "New status (optional)",
            tags = "Replace tags entirely. [] clears tags. Omit to leave unchanged.",
            priority = "Replace priority. Omit to leave unchanged.",
            meta_extra = "Shallow-merge into meta extensible bag. null value deletes a key."
        )
    )]
    async fn update(
        &self,
        auth: &AuthContext,
        id: String,
        title: Option<String>,
        body: Option<String>,
        status: Option<String>,
        tags: Option<Vec<String>>,
        priority: Option<String>,
        meta_extra: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        // AUTHZ-TENANT-GATE: this handler now requires auth (previously
        // anonymous-writable — a privilege escalation vector). Routed
        // through `TenantGate::update`, which:
        //   - returns NotFound for missing target,
        //   - returns Forbidden for cross-tenant write,
        //   - preserves the existing meta.extra["tenant"] (no hopping).
        let gate = TenantGate::from_auth(self.store.clone(), Some(auth)).await;
        let store_for_fetch = self.store.clone();
        stream! {
            let uuid = match uuid::Uuid::parse_str(&id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_id".into()), message: e.to_string() };
                    return;
                }
            };
            // Fetch existing for the in-place merge (the gate also fetches
            // for its visibility check; one extra read is acceptable for
            // the demo). If the caller can't see the facet, surface
            // not_found via the gate's update path below.
            let mut facet = match store_for_fetch.get_facet(uuid).await {
                Ok(f) => f,
                Err(StoreError::NotFound(_)) => {
                    yield TrakEvent::Error { code: Some("not_found".into()), message: format!("facet {id} not found") };
                    return;
                }
                Err(e) => {
                    yield TrakEvent::Error { code: Some("get_failed".into()), message: e.to_string() };
                    return;
                }
            };
            let update = FacetUpdate {
                title,
                body,
                status,
                tags,
                priority,
                meta_extra,
            };
            update.apply(&mut facet);
            // Match prior behavior: always bump updated_at on update calls,
            // even if every field was None (no observable change). This keeps
            // the existing test_update_status invariant.
            facet.updated_at = chrono::Utc::now();

            match gate.update(facet).await {
                Ok(facet) => yield TrakEvent::FacetUpdated { facet },
                Err(GateError::Unauthenticated) => yield TrakEvent::Error {
                    code: Some("unauthenticated".into()),
                    message: "update requires an authenticated tenant".into(),
                },
                Err(GateError::Forbidden) => yield TrakEvent::Error {
                    code: Some("forbidden".into()),
                    message: "cannot update facet owned by another tenant".into(),
                },
                Err(GateError::NotFound) => yield TrakEvent::Error {
                    code: Some("not_found".into()),
                    message: format!("facet {id} not found"),
                },
                Err(e) => yield TrakEvent::Error { code: Some("update_failed".into()), message: e.to_string() },
            }
        }
    }

    /// Delete a facet
    ///
    /// **AUTHZ-TENANT-GATE:** previously anonymous-writable. Now routed
    /// through `TenantGate::delete` which checks tenant ownership before
    /// deletion. Foreign-tenant delete attempts return `Forbidden`.
    #[plexus_macros::method(
        description = "Delete a facet by UUID (tenant-scoped)",
        params(id = "Facet UUID")
    )]
    async fn delete(
        &self,
        auth: &AuthContext,
        id: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let gate = TenantGate::from_auth(self.store.clone(), Some(auth)).await;
        stream! {
            let uuid = match uuid::Uuid::parse_str(&id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_id".into()), message: e.to_string() };
                    return;
                }
            };
            match gate.delete(uuid).await {
                Ok(()) => yield TrakEvent::FacetDeleted { id: uuid },
                Err(GateError::Unauthenticated) => yield TrakEvent::Error {
                    code: Some("unauthenticated".into()),
                    message: "delete requires an authenticated tenant".into(),
                },
                Err(GateError::Forbidden) => yield TrakEvent::Error {
                    code: Some("forbidden".into()),
                    message: "cannot delete facet owned by another tenant".into(),
                },
                Err(GateError::NotFound) => yield TrakEvent::Error {
                    code: Some("not_found".into()),
                    message: format!("facet {id} not found"),
                },
                Err(e) => yield TrakEvent::Error { code: Some("delete_failed".into()), message: e.to_string() },
            }
        }
    }

    /// Move a facet to a new parent
    #[plexus_macros::method(
        description = "Move a facet under a different parent (or to root)",
        params(
            id = "Facet UUID to move",
            new_parent_id = "New parent UUID (omit to make root)"
        )
    )]
    async fn move_to(
        &self,
        id: String,
        new_parent_id: Option<String>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            let uuid = match uuid::Uuid::parse_str(&id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_id".into()), message: e.to_string() };
                    return;
                }
            };
            let new_parent = match new_parent_id.as_deref().map(uuid::Uuid::parse_str).transpose() {
                Ok(v) => v,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_parent_id".into()), message: e.to_string() };
                    return;
                }
            };
            // Fetch old parent first for the event.
            let old_parent = match store.get_facet(uuid).await {
                Ok(f) => f.parent_id,
                Err(StoreError::NotFound(_)) => {
                    yield TrakEvent::Error { code: Some("not_found".into()), message: format!("facet {id} not found") };
                    return;
                }
                Err(e) => {
                    yield TrakEvent::Error { code: Some("get_failed".into()), message: e.to_string() };
                    return;
                }
            };
            match store.move_facet(uuid, new_parent).await {
                Ok(()) => yield TrakEvent::FacetMoved { id: uuid, old_parent, new_parent },
                Err(e) => yield TrakEvent::Error { code: Some("move_failed".into()), message: e.to_string() },
            }
        }
    }

    /// List facets (children of a parent, or roots)
    ///
    /// Optional `tags`, `tags_all`, `priority` filters (TRAK-API-3) post-filter
    /// the result set. Empty arrays / None mean "no filter" — default behavior
    /// is byte-for-byte identical to the prior implementation.
    #[plexus_macros::method(
        description = "List child facets under a parent (or roots). Optionally filter by tags / priority.",
        params(
            parent_id = "Parent UUID (omit for roots)",
            tags = "OR filter: keep facets whose tags include any of these",
            tags_all = "AND filter: keep facets whose tags include all of these",
            priority = "Keep facets whose priority is one of these"
        )
    )]
    async fn list(
        &self,
        auth: &AuthContext,
        parent_id: Option<String>,
        tags: Option<Vec<String>>,
        tags_all: Option<Vec<String>>,
        priority: Option<Vec<String>>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        // AUTHZ-TENANT-GATE: visibility-scoped listing. Foreign-tenant
        // facets are filtered out via `TenantGate::list_children`. The
        // tag/priority post-filter runs on the already-visibility-scoped
        // set so callers don't see "ghost" totals.
        let gate = TenantGate::from_auth(self.store.clone(), Some(auth)).await;
        let store = self.store.clone();
        stream! {
            let parent_uuid = match parent_id.as_deref().map(uuid::Uuid::parse_str).transpose() {
                Ok(v) => v,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_parent_id".into()), message: e.to_string() };
                    return;
                }
            };
            match gate.list_children(parent_uuid).await {
                Ok(facets) => {
                    let facets = filter_facets(facets, tags.as_deref(), tags_all.as_deref(), priority.as_deref());
                    let total = facets.len() as u32;
                    for facet in facets {
                        let child_count = store.count_children(Some(facet.id)).await.unwrap_or(0);
                        yield TrakEvent::FacetSummary {
                            id: facet.id,
                            title: facet.title,
                            status: facet.status,
                            depth: 0,
                            child_count,
                        };
                    }
                    yield TrakEvent::ListSummary { total };
                }
                Err(e) => yield TrakEvent::Error { code: Some("list_failed".into()), message: e.to_string() },
            }
        }
    }

    /// Get the full subtree rooted at a facet
    #[plexus_macros::method(
        description = "Recursively walk the subtree rooted at a facet",
        params(id = "Root facet UUID")
    )]
    async fn tree(&self, id: String) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            let uuid = match uuid::Uuid::parse_str(&id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_id".into()), message: e.to_string() };
                    return;
                }
            };
            match store.get_subtree(uuid).await {
                Ok(nodes) => {
                    let total = nodes.len() as u32;
                    for (facet, depth) in nodes {
                        let child_count = store.count_children(Some(facet.id)).await.unwrap_or(0);
                        yield TrakEvent::FacetSummary {
                            id: facet.id,
                            title: facet.title,
                            status: facet.status,
                            depth,
                            child_count,
                        };
                    }
                    yield TrakEvent::ListSummary { total };
                }
                Err(e) => yield TrakEvent::Error { code: Some("tree_failed".into()), message: e.to_string() },
            }
        }
    }

    /// Create a link (edge) between two facets
    #[plexus_macros::method(
        description = "Create a typed link between two facets",
        params(
            from_id = "Source facet UUID",
            to_id = "Target facet UUID",
            kind = "Edge kind: depends_on, blocks, relates_to, duplicates"
        )
    )]
    async fn link(
        &self,
        from_id: String,
        to_id: String,
        kind: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            let from = match uuid::Uuid::parse_str(&from_id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_from_id".into()), message: e.to_string() };
                    return;
                }
            };
            let to = match uuid::Uuid::parse_str(&to_id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_to_id".into()), message: e.to_string() };
                    return;
                }
            };
            let edge_kind: EdgeKind = match kind.parse() {
                Ok(k) => k,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_kind".into()), message: e };
                    return;
                }
            };
            let edge = Edge {
                from_id: from,
                to_id: to,
                kind: edge_kind,
                created_at: chrono::Utc::now(),
            };
            match store.add_edge(&edge).await {
                Ok(()) => yield TrakEvent::LinkCreated { edge },
                Err(e) => yield TrakEvent::Error { code: Some("link_failed".into()), message: e.to_string() },
            }
        }
    }

    /// Remove a link between two facets
    #[plexus_macros::method(
        description = "Remove a typed link between two facets",
        params(
            from_id = "Source facet UUID",
            to_id = "Target facet UUID",
            kind = "Edge kind to remove"
        )
    )]
    async fn unlink(
        &self,
        from_id: String,
        to_id: String,
        kind: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            let from = match uuid::Uuid::parse_str(&from_id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_from_id".into()), message: e.to_string() };
                    return;
                }
            };
            let to = match uuid::Uuid::parse_str(&to_id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_to_id".into()), message: e.to_string() };
                    return;
                }
            };
            let edge_kind: EdgeKind = match kind.parse() {
                Ok(k) => k,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_kind".into()), message: e };
                    return;
                }
            };
            match store.remove_edge(from, to, &edge_kind).await {
                Ok(()) => yield TrakEvent::LinkRemoved { from_id: from, to_id: to, kind },
                Err(e) => yield TrakEvent::Error { code: Some("unlink_failed".into()), message: e.to_string() },
            }
        }
    }

    /// List links for a facet
    #[plexus_macros::method(
        description = "List edges connected to a facet",
        params(
            id = "Facet UUID",
            direction = "outgoing, incoming, or both (default: both)",
            kind = "Filter by edge kind (optional)"
        )
    )]
    async fn links(
        &self,
        id: String,
        direction: Option<String>,
        kind: Option<String>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            let uuid = match uuid::Uuid::parse_str(&id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_id".into()), message: e.to_string() };
                    return;
                }
            };
            let dir = match direction.as_deref() {
                Some("outgoing") => Direction::Outgoing,
                Some("incoming") => Direction::Incoming,
                Some("both") | None => Direction::Both,
                Some(other) => {
                    yield TrakEvent::Error { code: Some("invalid_direction".into()), message: format!("unknown direction: {other}") };
                    return;
                }
            };
            let edge_kind: Option<EdgeKind> = match kind.as_deref().map(str::parse).transpose() {
                Ok(k) => k,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_kind".into()), message: e };
                    return;
                }
            };
            match store.get_edges(uuid, dir, edge_kind.as_ref()).await {
                Ok(edges) => {
                    for edge in edges {
                        yield TrakEvent::LinkDetail { edge };
                    }
                }
                Err(e) => yield TrakEvent::Error { code: Some("links_failed".into()), message: e.to_string() },
            }
        }
    }

    /// Find blocked facets
    #[plexus_macros::method(
        description = "Find facets that are blocked by non-done dependencies",
        params(parent_id = "Scope search to children of this parent (optional)")
    )]
    async fn blocked(
        &self,
        parent_id: Option<String>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            let parent_uuid = match parent_id.as_deref().map(uuid::Uuid::parse_str).transpose() {
                Ok(v) => v,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_parent_id".into()), message: e.to_string() };
                    return;
                }
            };
            let facets = match store.list_children(parent_uuid).await {
                Ok(f) => f,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("list_failed".into()), message: e.to_string() };
                    return;
                }
            };
            for facet in facets {
                let deps = match store.get_edges(facet.id, Direction::Outgoing, Some(&EdgeKind::DependsOn)).await {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let mut blockers = Vec::new();
                for dep in &deps {
                    if let Ok(target) = store.get_facet(dep.to_id).await {
                        if target.status != "done" {
                            blockers.push(dep.to_id);
                        }
                    }
                }
                if !blockers.is_empty() {
                    yield TrakEvent::Blocked { facet, blocked_by: blockers };
                }
            }
        }
    }

    /// Full-text search across facets
    ///
    /// Optional tag/priority filters post-filter FTS5 results. FTS5 ranking
    /// order is unchanged when no filters apply (the filter is a stable
    /// retain over the already-sorted result vec).
    #[plexus_macros::method(
        description = "Full-text search across facet titles and bodies. Optionally filter by tags / priority.",
        params(
            query = "Search query (FTS5 syntax)",
            tags = "OR filter: keep facets whose tags include any of these",
            tags_all = "AND filter: keep facets whose tags include all of these",
            priority = "Keep facets whose priority is one of these"
        )
    )]
    async fn search(
        &self,
        query: String,
        tags: Option<Vec<String>>,
        tags_all: Option<Vec<String>>,
        priority: Option<Vec<String>>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            match store.search(&query).await {
                Ok(results) => {
                    let tags_any = tags.as_deref().filter(|t| !t.is_empty());
                    let tags_all = tags_all.as_deref().filter(|t| !t.is_empty());
                    let priority = priority.as_deref().filter(|p| !p.is_empty());
                    let no_filter = tags_any.is_none() && tags_all.is_none() && priority.is_none();
                    for (facet, score) in results {
                        if !no_filter {
                            // Wrap the single facet so we can reuse the shared
                            // filter logic and keep the matrix tested in one place.
                            let kept = filter_facets(vec![facet.clone()], tags_any, tags_all, priority);
                            if kept.is_empty() {
                                continue;
                            }
                        }
                        yield TrakEvent::SearchResult { facet, score: Some(score) };
                    }
                }
                Err(e) => yield TrakEvent::Error { code: Some("search_failed".into()), message: e.to_string() },
            }
        }
    }

    /// Regex search across facet titles and bodies
    #[plexus_macros::method(
        description = "Search facets by regex pattern against title and body. Returns all matches.",
        params(
            pattern = "Regex pattern (Rust regex syntax)",
            status = "Filter by status (optional)",
            parent_id = "Scope to children of this facet (optional)",
            tags = "OR filter: keep facets whose tags include any of these",
            tags_all = "AND filter: keep facets whose tags include all of these",
            priority = "Keep facets whose priority is one of these"
        )
    )]
    async fn grep(
        &self,
        pattern: String,
        status: Option<String>,
        parent_id: Option<String>,
        tags: Option<Vec<String>>,
        tags_all: Option<Vec<String>>,
        priority: Option<Vec<String>>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            let re = match regex::Regex::new(&pattern) {
                Ok(r) => r,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("invalid_regex".into()),
                        message: format!("Bad pattern: {e}"),
                    };
                    return;
                }
            };

            // Load facets to scan
            let facets = if let Some(ref pid) = parent_id {
                match uuid::Uuid::parse_str(pid) {
                    Ok(parent_uuid) => {
                        // Get full subtree under parent
                        match store.get_subtree(parent_uuid).await {
                            Ok(items) => items.into_iter().map(|(f, _depth)| f).collect::<Vec<_>>(),
                            Err(e) => {
                                yield TrakEvent::Error { code: Some("grep_failed".into()), message: e.to_string() };
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        yield TrakEvent::Error { code: Some("invalid_id".into()), message: e.to_string() };
                        return;
                    }
                }
            } else {
                // Scan all roots + their subtrees
                match store.list_roots().await {
                    Ok(roots) => {
                        let mut all = Vec::new();
                        for root in &roots {
                            all.push(root.clone());
                            if let Ok(children) = store.get_subtree(root.id).await {
                                all.extend(children.into_iter().map(|(f, _)| f));
                            }
                        }
                        all
                    }
                    Err(e) => {
                        yield TrakEvent::Error { code: Some("grep_failed".into()), message: e.to_string() };
                        return;
                    }
                }
            };

            // Apply tag/priority filters before regex (cheap reject of irrelevant
            // facets first; preserves doc order so the output sequence matches
            // prior behavior when no tag/priority filters are provided).
            let facets = filter_facets(facets, tags.as_deref(), tags_all.as_deref(), priority.as_deref());

            let mut count = 0u32;
            for facet in &facets {
                // Filter by status if specified
                if let Some(ref s) = status {
                    if &facet.status != s { continue; }
                }

                let title_match = re.is_match(&facet.title);
                let body_match = facet.body.as_deref().is_some_and(|b| re.is_match(b));

                if title_match || body_match {
                    yield TrakEvent::SearchResult {
                        facet: facet.clone(),
                        score: None,
                    };
                    count += 1;
                }
            }

            yield TrakEvent::Info { message: format!("{count} matches") };
        }
    }

    /// Check out a facet subtree to disk as markdown files
    #[plexus_macros::method(
        description = "Write facet subtree to disk as markdown for editing",
        params(
            id = "Root facet UUID",
            path = "Working directory path (will be created)"
        )
    )]
    async fn checkout(
        &self,
        auth: &AuthContext,
        id: String,
        path: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let _ = auth;
        let store = self.store.clone();
        stream! {
            let root = match uuid::Uuid::parse_str(&id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error { code: Some("invalid_id".into()), message: e.to_string() };
                    return;
                }
            };
            let base = std::path::Path::new(&path);
            match crate::checkout::checkout(store.as_ref(), root, base).await {
                Ok(manifest) => {
                    let count = manifest.facets.len() as u32;
                    yield TrakEvent::CheckoutComplete {
                        root_id: root,
                        file_count: count,
                        base_path: path,
                    };
                }
                Err(e) => {
                    yield TrakEvent::Error { code: Some("checkout_failed".into()), message: e.to_string() };
                }
            }
        }
    }

    /// Show pending changes between disk and trak
    #[plexus_macros::method(
        description = "Show diff between checked-out files and trak state",
        params(path = "Working directory path")
    )]
    async fn diff(
        &self,
        auth: &AuthContext,
        path: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let _ = auth;
        let store = self.store.clone();
        stream! {
            let base = std::path::Path::new(&path);
            match crate::checkout::diff(store.as_ref(), base).await {
                Ok(entries) => {
                    let count = entries.len();
                    for entry in entries {
                        let detail = match &entry {
                            crate::checkout::DiffEntry::Conflict { reason, .. } => Some(reason.clone()),
                            crate::checkout::DiffEntry::Moved { old_path, new_path, .. } => {
                                Some(format!("{old_path} -> {new_path}"))
                            }
                            _ => None,
                        };
                        yield TrakEvent::DiffEntryEvent {
                            kind: entry.kind().to_string(),
                            path: entry.path().to_string(),
                            uuid: entry.uuid(),
                            detail,
                        };
                    }
                    yield TrakEvent::Info { message: format!("{count} change(s)") };
                }
                Err(e) => {
                    yield TrakEvent::Error { code: Some("diff_failed".into()), message: e.to_string() };
                }
            }
        }
    }

    /// Apply changes from disk back into trak
    #[plexus_macros::method(
        description = "Sync local file changes back into trak",
        params(
            path = "Working directory path",
            force = "Apply changes even if conflicts detected (default: false)"
        )
    )]
    async fn flush(
        &self,
        auth: &AuthContext,
        path: String,
        force: Option<bool>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let owner = owner_from_auth(auth);
        let force = force.unwrap_or(false);
        stream! {
            let base = std::path::Path::new(&path);
            match crate::checkout::flush(store.as_ref(), base, &owner, force).await {
                Ok(report) => {
                    yield TrakEvent::FlushReport {
                        created: report.created,
                        modified: report.modified,
                        deleted: report.deleted,
                        moved: report.moved,
                        conflicts: report.conflicts.len() as u32,
                    };
                    for c in report.conflicts {
                        yield TrakEvent::DiffEntryEvent {
                            kind: c.kind,
                            path: c.path,
                            uuid: c.uuid,
                            detail: c.detail,
                        };
                    }
                }
                Err(e) => {
                    yield TrakEvent::Error { code: Some("flush_failed".into()), message: e.to_string() };
                }
            }
        }
    }

    /// Import plan epics from a workspace directory into trak facets.
    ///
    /// Scans for `plans/` directories across all repos in the workspace,
    /// parses markdown tickets (frontmatter and inline formats), creates
    /// a facet hierarchy (repo → epic → ticket), and wires dependency edges.
    #[plexus_macros::method(params(
        path = "Path to workspace root directory to scan for plans/",
        dry_run = "Preview without creating facets (default: false)"
    ))]
    pub async fn import_plans(
        &self,
        auth: &AuthContext,
        path: String,
        dry_run: Option<bool>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let owner = owner_from_auth(auth);
        let tenant = tenant_from_auth(auth);
        let is_dry_run = dry_run.unwrap_or(false);

        stream! {
            let workspace_path = std::path::Path::new(&path);
            if !workspace_path.is_dir() {
                yield TrakEvent::Error {
                    code: Some("invalid_path".into()),
                    message: format!("Not a directory: {path}"),
                };
                return;
            }

            yield TrakEvent::Info {
                message: format!("Scanning {} for plan files...", path),
            };

            let tickets = crate::import::scan_plans(workspace_path);

            yield TrakEvent::Info {
                message: format!("Found {} tickets across {} epics",
                    tickets.len(),
                    tickets.iter().map(|t| &t.epic).collect::<std::collections::HashSet<_>>().len(),
                ),
            };

            // Show what we found
            let mut by_repo: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
            for t in &tickets {
                by_repo.entry(&t.repo).or_default().push(&t.id);
            }
            for (repo, ids) in &by_repo {
                yield TrakEvent::Info {
                    message: format!("  {}: {} tickets", repo, ids.len()),
                };
            }

            if is_dry_run {
                yield TrakEvent::Info {
                    message: "[dry run] Would import the above. Pass --dry_run false to create facets.".into(),
                };
                return;
            }

            let report = crate::import::import_into_trak(
                store.as_ref(),
                &tickets,
                &owner,
                tenant.as_deref(),
            ).await;

            yield TrakEvent::Info {
                message: format!(
                    "Import complete: {} repos, {} epics, {} tickets, {} dependency edges",
                    report.repos_created,
                    report.epics_created,
                    report.tickets_created,
                    report.edges_created,
                ),
            };
        }
    }
}
