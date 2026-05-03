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
