use async_stream::stream;
use futures::Stream;

use crate::events::TrakEvent;

/// DiscussHub — threaded discussions on facets (stub).
#[derive(Clone)]
pub struct DiscussHub;

impl DiscussHub {
    pub fn new() -> Self {
        Self
    }
}

#[plexus_macros::activation(
    namespace = "discuss",
    version = "0.1.0",
    description = "Threaded discussions on facets (stub)"
)]
impl DiscussHub {
    /// Post a comment on a facet
    #[plexus_macros::method(
        description = "Post a comment on a facet",
        params(facet_id = "Facet UUID", body = "Comment body")
    )]
    async fn post(
        &self,
        facet_id: String,
        body: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        stream! {
            let _ = (&facet_id, &body);
            yield TrakEvent::Error { code: Some("not_implemented".into()), message: "discuss.post not yet implemented".into() };
        }
    }

    /// List comments on a facet
    #[plexus_macros::method(
        description = "List comments on a facet",
        params(facet_id = "Facet UUID")
    )]
    async fn list(
        &self,
        facet_id: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        stream! {
            let _ = &facet_id;
            yield TrakEvent::Error { code: Some("not_implemented".into()), message: "discuss.list not yet implemented".into() };
        }
    }
}
