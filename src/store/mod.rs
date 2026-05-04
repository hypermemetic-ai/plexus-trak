pub mod discuss;
pub mod identity;
pub mod sqlite;

use async_trait::async_trait;
use uuid::Uuid;

use crate::types::{Edge, EdgeKind, Facet};

/// Direction for edge queries.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Outgoing,
    Incoming,
    Both,
}

/// Errors from the facet store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("facet not found: {0}")]
    NotFound(Uuid),
    #[error("database error: {0}")]
    Db(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::Db(e.to_string())
    }
}

/// Async storage trait for facets and edges.
#[async_trait]
pub trait FacetStore: Send + Sync + 'static {
    async fn create_facet(&self, facet: &Facet) -> Result<(), StoreError>;
    async fn get_facet(&self, id: Uuid) -> Result<Facet, StoreError>;
    async fn update_facet(&self, facet: &Facet) -> Result<(), StoreError>;
    async fn delete_facet(&self, id: Uuid) -> Result<(), StoreError>;
    async fn move_facet(&self, id: Uuid, new_parent: Option<Uuid>) -> Result<(), StoreError>;
    async fn list_children(&self, parent_id: Option<Uuid>) -> Result<Vec<Facet>, StoreError>;
    async fn list_roots(&self) -> Result<Vec<Facet>, StoreError>;
    async fn get_ancestors(&self, id: Uuid) -> Result<Vec<Facet>, StoreError>;
    async fn get_subtree(&self, root_id: Uuid) -> Result<Vec<(Facet, u32)>, StoreError>;
    async fn count_children(&self, parent_id: Option<Uuid>) -> Result<u32, StoreError>;

    async fn add_edge(&self, edge: &Edge) -> Result<(), StoreError>;
    async fn remove_edge(
        &self,
        from_id: Uuid,
        to_id: Uuid,
        kind: &EdgeKind,
    ) -> Result<(), StoreError>;
    async fn get_edges(
        &self,
        facet_id: Uuid,
        direction: Direction,
        kind: Option<&EdgeKind>,
    ) -> Result<Vec<Edge>, StoreError>;

    async fn search(&self, query: &str) -> Result<Vec<(Facet, f64)>, StoreError>;
}
