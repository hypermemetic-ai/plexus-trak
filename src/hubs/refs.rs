use async_stream::stream;
use futures::Stream;

use crate::events::TrakEvent;

/// RefsHub — external reference attachments (stub).
#[derive(Clone)]
pub struct RefsHub;

impl RefsHub {
    pub fn new() -> Self {
        Self
    }
}

#[plexus_macros::activation(
    namespace = "refs",
    version = "0.1.0",
    description = "External reference attachments (stub)"
)]
impl RefsHub {
    /// Attach an external reference to a facet
    #[plexus_macros::method(
        description = "Attach an external reference (URL, file, commit) to a facet",
        params(facet_id = "Facet UUID", uri = "Reference URI", label = "Human-readable label")
    )]
    async fn attach(
        &self,
        facet_id: String,
        uri: String,
        label: Option<String>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        stream! {
            let _ = (&facet_id, &uri, &label);
            yield TrakEvent::Error { code: Some("not_implemented".into()), message: "refs.attach not yet implemented".into() };
        }
    }

    /// List references on a facet
    #[plexus_macros::method(
        description = "List external references attached to a facet",
        params(facet_id = "Facet UUID")
    )]
    async fn list(
        &self,
        facet_id: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        stream! {
            let _ = &facet_id;
            yield TrakEvent::Error { code: Some("not_implemented".into()), message: "refs.list not yet implemented".into() };
        }
    }
}
