use async_stream::stream;
use futures::Stream;

use crate::events::TrakEvent;

/// AccessHub — permission and role management (stub).
#[derive(Clone)]
pub struct AccessHub;

impl AccessHub {
    pub fn new() -> Self {
        Self
    }
}

#[plexus_macros::activation(
    namespace = "access",
    version = "0.1.0",
    description = "Permission and role management (stub)"
)]
impl AccessHub {
    /// Check if an identity has access to a facet
    #[plexus_macros::method(
        description = "Check access for an identity on a facet",
        params(facet_id = "Facet UUID", identity = "Identity to check")
    )]
    async fn check(
        &self,
        facet_id: String,
        identity: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        stream! {
            let _ = (&facet_id, &identity);
            yield TrakEvent::Error { code: Some("not_implemented".into()), message: "access.check not yet implemented".into() };
        }
    }

    /// Grant a role on a facet
    #[plexus_macros::method(
        description = "Grant a role to an identity on a facet",
        params(facet_id = "Facet UUID", identity = "Identity", role = "Role to grant")
    )]
    async fn grant(
        &self,
        facet_id: String,
        identity: String,
        role: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        stream! {
            let _ = (&facet_id, &identity, &role);
            yield TrakEvent::Error { code: Some("not_implemented".into()), message: "access.grant not yet implemented".into() };
        }
    }
}
