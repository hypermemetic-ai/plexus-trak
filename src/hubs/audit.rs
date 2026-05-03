use async_stream::stream;
use futures::Stream;

use crate::events::TrakEvent;

/// AuditHub — event audit log (stub).
#[derive(Clone)]
pub struct AuditHub;

impl AuditHub {
    pub fn new() -> Self {
        Self
    }
}

#[plexus_macros::activation(
    namespace = "audit",
    version = "0.1.0",
    description = "Event audit log (stub)"
)]
impl AuditHub {
    /// Get audit trail for a facet
    #[plexus_macros::method(
        description = "Get audit trail for a facet",
        params(facet_id = "Facet UUID")
    )]
    async fn trail(
        &self,
        facet_id: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        stream! {
            let _ = &facet_id;
            yield TrakEvent::Error { code: Some("not_implemented".into()), message: "audit.trail not yet implemented".into() };
        }
    }

    /// Get recent audit events across all facets
    #[plexus_macros::method(
        description = "Get recent audit events",
        params(limit = "Max events to return")
    )]
    async fn recent(
        &self,
        limit: Option<u32>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        stream! {
            let _ = limit;
            yield TrakEvent::Error { code: Some("not_implemented".into()), message: "audit.recent not yet implemented".into() };
        }
    }
}
