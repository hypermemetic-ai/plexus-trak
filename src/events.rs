use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{Edge, Facet};

/// All events emitted by trak activations.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TrakEvent {
    // ── Facet lifecycle ─────────────────────────────────────────────
    FacetCreated {
        facet: Facet,
    },
    FacetUpdated {
        facet: Facet,
    },
    FacetDeleted {
        id: Uuid,
    },
    FacetMoved {
        id: Uuid,
        old_parent: Option<Uuid>,
        new_parent: Option<Uuid>,
    },
    FacetDetail {
        facet: Facet,
    },
    FacetSummary {
        id: Uuid,
        title: String,
        status: String,
        depth: u32,
        child_count: u32,
    },

    // ── Links / edges ───────────────────────────────────────────────
    LinkCreated {
        edge: Edge,
    },
    LinkRemoved {
        from_id: Uuid,
        to_id: Uuid,
        kind: String,
    },
    LinkDetail {
        edge: Edge,
    },

    // ── Queries ─────────────────────────────────────────────────────
    Blocked {
        facet: Facet,
        blocked_by: Vec<Uuid>,
    },
    SearchResult {
        facet: Facet,
        #[serde(skip_serializing_if = "Option::is_none")]
        score: Option<f64>,
    },
    ListSummary {
        total: u32,
    },

    // ── Identity / auth ──────────────────────────────────────────────
    UserRegistered {
        user_id: String,
        username: String,
    },
    LoginSuccess {
        access_token: String,
        refresh_token: String,
        expires_in: u64,
    },
    TokenRefreshed {
        access_token: String,
        expires_in: u64,
    },
    UserInfo {
        user_id: String,
        username: String,
        display_name: Option<String>,
        roles: Vec<String>,
        tenant: Option<String>,
    },
    ApiKeyCreated {
        key_id: String,
        name: String,
        /// Raw key — returned only once at creation time.
        key: String,
    },
    ApiKeyRevoked {
        key_id: String,
    },
    ApiKeyList {
        keys: Vec<serde_json::Value>,
    },
    UserList {
        users: Vec<serde_json::Value>,
    },

    // ── Stub domains (future) ───────────────────────────────────────
    DiscussEvent {
        message: String,
    },
    AuditEvent {
        message: String,
    },
    AccessEvent {
        message: String,
    },
    CollabEvent {
        message: String,
    },
    RefsEvent {
        message: String,
    },

    // ── Meta ────────────────────────────────────────────────────────
    Error {
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
        message: String,
    },
    Info {
        message: String,
    },
}
