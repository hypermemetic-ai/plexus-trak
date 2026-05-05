//! DocsHub — machine-readable self-documentation.
//!
//! The /docs/ root facet (a facet titled "docs" at the top level) holds
//! curated documentation as child facets. This hub provides a typed view
//! over those facets so machine consumers (LLM agents, codegen) can learn
//! the service without reading source.
//!
//! v1 implements: about(), guides(), guide(slug_or_id).
//! Future: surface() (introspection), examples(), glossary(), changelog().

use std::sync::Arc;

use async_stream::stream;
use futures::Stream;
use uuid::Uuid;

use crate::events::TrakEvent;
use crate::store::FacetStore;
use crate::types::Facet;

/// Service identity. Returned by `about()`.
const SERVICE_NAME: &str = "trak";
const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");
const SERVICE_DESCRIPTION: &str =
    "Recursive work tracker. Facets within facets. Identity, content, and relationships.";

/// DocsHub — read-only view over the /docs/ facet subtree.
#[derive(Clone)]
pub struct DocsHub {
    store: Arc<dyn FacetStore>,
}

impl DocsHub {
    pub fn new(store: Arc<dyn FacetStore>) -> Self {
        Self { store }
    }
}

/// Find the root facet titled "docs" (case-insensitive).
async fn find_docs_root(store: &dyn FacetStore) -> Option<Facet> {
    let roots = store.list_roots().await.ok()?;
    roots
        .into_iter()
        .find(|f| f.title.eq_ignore_ascii_case("docs"))
}

/// Slugify a title for URL-friendly references.
fn slugify(title: &str) -> String {
    title
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Take the first non-empty paragraph as a summary.
fn summarize(body: &str) -> String {
    body.split("\n\n")
        .find(|p| !p.trim().is_empty() && !p.trim_start().starts_with('#'))
        .or_else(|| body.split("\n\n").find(|p| !p.trim().is_empty()))
        .map(|s| {
            let trimmed = s.trim();
            if trimmed.len() > 200 {
                format!("{}...", &trimmed[..200])
            } else {
                trimmed.to_string()
            }
        })
        .unwrap_or_default()
}

#[plexus_macros::activation(
    namespace = "docs",
    version = "0.1.0",
    description = "Machine-readable self-documentation for trak",
    auth_posture = "public"
)]
impl DocsHub {
    /// Service identity — name, version, description.
    ///
    /// Static information about this trak instance. Always available
    /// regardless of authentication state.
    #[plexus_macros::method(description = "Service identity (name, version, description)")]
    async fn about(&self) -> impl Stream<Item = TrakEvent> + Send + 'static {
        stream! {
            yield TrakEvent::DocsAbout {
                name: SERVICE_NAME.to_string(),
                version: SERVICE_VERSION.to_string(),
                description: SERVICE_DESCRIPTION.to_string(),
                hubs: vec![
                    "facet".to_string(),
                    "identity".to_string(),
                    "discuss".to_string(),
                    "audit".to_string(),
                    "access".to_string(),
                    "collab".to_string(),
                    "refs".to_string(),
                    "docs".to_string(),
                ],
            };
        }
    }

    /// List all guides (children of the /docs/ root facet).
    ///
    /// Returns one DocsGuide event per child of the root facet titled
    /// "docs". Each event carries id, slug, title, and a summary
    /// (first non-heading paragraph). The full body is omitted — call
    /// `guide` to fetch it.
    #[plexus_macros::method(description = "List documentation guides — children of the root facet titled 'docs'")]
    async fn guides(&self) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            let root = match find_docs_root(store.as_ref()).await {
                Some(r) => r,
                None => {
                    yield TrakEvent::Info {
                        message: "No /docs/ root facet found. Create a top-level facet titled 'docs' to start.".into(),
                    };
                    return;
                }
            };

            let children = match store.list_children(Some(root.id)).await {
                Ok(c) => c,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("guides_failed".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };

            let mut count = 0u32;
            for facet in &children {
                let body = facet.body.as_deref().unwrap_or("");
                yield TrakEvent::DocsGuide {
                    id: facet.id.to_string(),
                    slug: slugify(&facet.title),
                    title: facet.title.clone(),
                    summary: summarize(body),
                    body: None,
                    updated_at: facet.updated_at,
                };
                count += 1;
            }

            yield TrakEvent::Info {
                message: format!("{count} guide{} under /docs/", if count == 1 { "" } else { "s" }),
            };
        }
    }

    /// Fetch one guide by slug or UUID.
    ///
    /// Returns the full body of a guide. Accepts either the human-readable
    /// slug (e.g. "logging-in-to-trak") derived from the title, or the
    /// raw facet UUID.
    #[plexus_macros::method(
        description = "Fetch one guide's full body by slug or UUID",
        params(slug_or_id = "Guide slug (kebab-case from title) or facet UUID")
    )]
    async fn guide(
        &self,
        slug_or_id: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            // Try as UUID first
            if let Ok(uuid) = Uuid::parse_str(&slug_or_id) {
                match store.get_facet(uuid).await {
                    Ok(f) => {
                        yield TrakEvent::DocsGuide {
                            id: f.id.to_string(),
                            slug: slugify(&f.title),
                            title: f.title.clone(),
                            summary: summarize(f.body.as_deref().unwrap_or("")),
                            body: f.body.clone(),
                            updated_at: f.updated_at,
                        };
                        return;
                    }
                    Err(_) => {
                        // Fall through to slug search
                    }
                }
            }

            // Search by slug under /docs/
            let root = match find_docs_root(store.as_ref()).await {
                Some(r) => r,
                None => {
                    yield TrakEvent::Error {
                        code: Some("no_docs_root".into()),
                        message: "No /docs/ root facet found".into(),
                    };
                    return;
                }
            };

            let children = match store.list_children(Some(root.id)).await {
                Ok(c) => c,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("guide_failed".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };

            let target_slug = slugify(&slug_or_id);
            let matched = children.iter().find(|f| {
                slugify(&f.title) == target_slug
                    || slugify(&f.title).contains(&target_slug)
            });

            match matched {
                Some(f) => yield TrakEvent::DocsGuide {
                    id: f.id.to_string(),
                    slug: slugify(&f.title),
                    title: f.title.clone(),
                    summary: summarize(f.body.as_deref().unwrap_or("")),
                    body: f.body.clone(),
                    updated_at: f.updated_at,
                },
                None => yield TrakEvent::Error {
                    code: Some("guide_not_found".into()),
                    message: format!("No guide matching '{slug_or_id}' under /docs/"),
                },
            }
        }
    }
}
