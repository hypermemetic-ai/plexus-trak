use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A facet — the universal unit of tracked work.
///
/// Facets are recursive: every facet can contain child facets,
/// forming an arbitrarily deep tree.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Facet {
    pub id: Uuid,
    /// Parent facet ID. None = root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Uuid>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub status: String,
    pub owner: String,
    pub meta: FacetMeta,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Extensible metadata on a facet.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct FacetMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Arbitrary JSON key-value pairs.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Input shape for creating a new facet.
///
/// Mirrors `Facet` shape so adding a new field on `FacetMeta` flows through
/// to the API automatically. Construct from RPC inputs in `FacetHub::create`.
///
/// `meta_extra` is shallow-merged into the resulting `FacetMeta.extra` bag —
/// callers attach arbitrary domain metadata without schema changes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct NewFacet {
    /// Required. Non-empty after trimming.
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Uuid>,
    /// Defaults to "open" when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Defaults to empty (None) when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    /// Extra metadata merged into `FacetMeta.extra`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_extra: Option<serde_json::Map<String, serde_json::Value>>,
}

impl NewFacet {
    /// Validate that the new-facet input is well-formed (title not empty).
    pub fn validate(&self) -> Result<(), String> {
        if self.title.trim().is_empty() {
            return Err("title must be non-empty".into());
        }
        Ok(())
    }

    /// Materialize a `Facet` from this input, given an owner and optional
    /// tenant (which is added to `meta.extra` to match prior server behavior).
    pub fn into_facet(self, owner: String, tenant: Option<String>) -> Facet {
        let now = chrono::Utc::now();
        let mut meta = FacetMeta {
            priority: self.priority,
            tags: self.tags,
            extra: self.meta_extra.unwrap_or_default(),
        };
        if let Some(t) = tenant {
            // Don't overwrite an explicitly-provided tenant in meta_extra.
            meta.extra
                .entry("tenant".to_string())
                .or_insert(serde_json::Value::String(t));
        }
        Facet {
            id: Uuid::new_v4(),
            parent_id: self.parent_id,
            title: self.title,
            body: self.body,
            status: self.status.unwrap_or_else(|| "open".into()),
            owner,
            meta,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Input shape for updating a facet. Every field is optional — `None` means
/// "leave the existing value unchanged". Setting `tags: Some(vec![])` clears
/// tags. Setting `priority: Some("...")` replaces priority; there is no way
/// to clear priority via this type — pass `meta_extra` for finer control if
/// needed in the future.
///
/// `parent_id` is intentionally absent — use `FacetHub::move_to`.
///
/// `meta_extra` semantics: shallow merge into the existing `FacetMeta.extra`
/// bag. A JSON `null` value for a key deletes that key from `extra`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct FacetUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_extra: Option<serde_json::Map<String, serde_json::Value>>,
}

impl FacetUpdate {
    /// Apply this update in-place to an existing facet. Returns `true` if any
    /// field changed (so callers can short-circuit unnecessary writes).
    pub fn apply(self, facet: &mut Facet) -> bool {
        let mut changed = false;
        if let Some(t) = self.title {
            facet.title = t;
            changed = true;
        }
        if let Some(b) = self.body {
            facet.body = Some(b);
            changed = true;
        }
        if let Some(s) = self.status {
            facet.status = s;
            changed = true;
        }
        if let Some(tags) = self.tags {
            // Some(vec![]) explicitly clears tags. Some(vec![..]) replaces them.
            facet.meta.tags = Some(tags);
            changed = true;
        }
        if let Some(p) = self.priority {
            facet.meta.priority = Some(p);
            changed = true;
        }
        if let Some(extra) = self.meta_extra {
            // Shallow-merge: each key in `extra` overwrites the corresponding
            // key in the existing meta.extra bag. A JSON null value DELETES
            // the key (per the TRAK-API-2 contract).
            for (k, v) in extra {
                if v.is_null() {
                    facet.meta.extra.remove(&k);
                } else {
                    facet.meta.extra.insert(k, v);
                }
                changed = true;
            }
        }
        if changed {
            facet.updated_at = chrono::Utc::now();
        }
        changed
    }
}

/// A typed edge between two facets.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Edge {
    pub from_id: Uuid,
    pub to_id: Uuid,
    pub kind: EdgeKind,
    pub created_at: DateTime<Utc>,
}

/// The kind of relationship an edge represents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    DependsOn,
    Blocks,
    RelatesTo,
    Duplicates,
}

impl std::fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeKind::DependsOn => write!(f, "depends_on"),
            EdgeKind::Blocks => write!(f, "blocks"),
            EdgeKind::RelatesTo => write!(f, "relates_to"),
            EdgeKind::Duplicates => write!(f, "duplicates"),
        }
    }
}

impl std::str::FromStr for EdgeKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "depends_on" => Ok(EdgeKind::DependsOn),
            "blocks" => Ok(EdgeKind::Blocks),
            "relates_to" => Ok(EdgeKind::RelatesTo),
            "duplicates" => Ok(EdgeKind::Duplicates),
            other => Err(format!("unknown edge kind: {other}")),
        }
    }
}
