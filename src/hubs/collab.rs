use async_stream::stream;
use futures::Stream;

use crate::events::TrakEvent;

/// CollabHub — real-time collaboration features (stub).
#[derive(Clone)]
pub struct CollabHub;

impl CollabHub {
    pub fn new() -> Self {
        Self
    }
}

#[plexus_macros::activation(
    namespace = "collab",
    version = "0.1.0",
    description = "Real-time collaboration features (stub)"
)]
impl CollabHub {
    /// List active collaborators on a facet
    #[plexus_macros::method(
        description = "List active collaborators on a facet",
        params(facet_id = "Facet UUID")
    )]
    async fn who(
        &self,
        facet_id: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        stream! {
            let _ = &facet_id;
            yield TrakEvent::Error { code: Some("not_implemented".into()), message: "collab.who not yet implemented".into() };
        }
    }

    /// Assign a facet to an identity
    #[plexus_macros::method(
        description = "Assign a facet to a collaborator",
        params(facet_id = "Facet UUID", identity = "Assignee identity")
    )]
    async fn assign(
        &self,
        facet_id: String,
        identity: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        stream! {
            let _ = (&facet_id, &identity);
            yield TrakEvent::Error { code: Some("not_implemented".into()), message: "collab.assign not yet implemented".into() };
        }
    }
}
