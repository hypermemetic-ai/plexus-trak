use std::sync::Arc;

use async_stream::stream;
use chrono::Utc;
use futures::Stream;
use plexus_core::plexus::AuthContext;
use uuid::Uuid;

use crate::events::TrakEvent;
use crate::store::discuss::{Comment, DiscussStore};

/// DiscussHub — comments and threaded discussion on facets.
#[derive(Clone)]
pub struct DiscussHub {
    store: Arc<DiscussStore>,
}

impl DiscussHub {
    pub fn new(store: Arc<DiscussStore>) -> Self {
        Self { store }
    }
}

/// Author user_id for a (possibly anonymous) auth context.
fn author_from_auth(auth: &AuthContext) -> String {
    if auth.user_id.is_empty() {
        "anonymous".to_string()
    } else {
        auth.user_id.clone()
    }
}

/// Optional display name (falls back to username metadata if present).
fn author_name_from_auth(auth: &AuthContext) -> Option<String> {
    auth.get_metadata_string("display_name")
        .or_else(|| auth.get_metadata_string("username"))
}

#[plexus_macros::activation(
    namespace = "discuss",
    version = "0.1.0",
    description = "Comments and threaded discussion on facets",
    auth_posture = "mixed"
)]
impl DiscussHub {
    /// Add a comment to a facet
    #[plexus_macros::method(
        description = "Post a comment on a facet (markdown supported). Anyone may comment; only the author may later edit/delete.",
        params(
            facet_id = "Facet UUID to comment on",
            body = "Comment body (markdown supported)",
            parent_comment_id = "Parent comment UUID for a threaded reply (optional)"
        )
    )]
    async fn comment(
        &self,
        auth: &AuthContext,
        facet_id: String,
        body: String,
        parent_comment_id: Option<String>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let author = author_from_auth(auth);
        let author_name = author_name_from_auth(auth);
        stream! {
            let facet_uuid = match Uuid::parse_str(&facet_id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("invalid_facet_id".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };
            let parent_uuid = match parent_comment_id.as_deref().map(Uuid::parse_str).transpose() {
                Ok(v) => v,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("invalid_parent_comment_id".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };

            if body.trim().is_empty() {
                yield TrakEvent::Error {
                    code: Some("empty_body".into()),
                    message: "comment body cannot be empty".into(),
                };
                return;
            }

            let now = Utc::now();
            let comment = Comment {
                id: Uuid::new_v4(),
                facet_id: facet_uuid,
                author,
                author_name,
                body,
                created_at: now,
                updated_at: now,
                edited: false,
                parent_comment_id: parent_uuid,
            };

            match store.create_comment(&comment).await {
                Ok(()) => yield TrakEvent::CommentAdded { comment },
                Err(e) => yield TrakEvent::Error {
                    code: Some("comment_failed".into()),
                    message: e.to_string(),
                },
            }
        }
    }

    /// List comments on a facet, oldest first
    #[plexus_macros::method(
        description = "List comments on a facet, oldest first (chronological). Supports pagination.",
        params(
            facet_id = "Facet UUID",
            limit = "Max comments to return (default: 50)",
            offset = "Skip N comments for pagination (default: 0)"
        )
    )]
    async fn list(
        &self,
        facet_id: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            let facet_uuid = match Uuid::parse_str(&facet_id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("invalid_facet_id".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };
            let lim = limit.unwrap_or(50);
            let off = offset.unwrap_or(0);

            let total = match store.count_comments(facet_uuid).await {
                Ok(t) => t,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("count_failed".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };

            match store.list_comments(facet_uuid, lim, off).await {
                Ok(comments) => yield TrakEvent::CommentList { comments, total },
                Err(e) => yield TrakEvent::Error {
                    code: Some("list_failed".into()),
                    message: e.to_string(),
                },
            }
        }
    }

    /// Get a single comment by ID
    #[plexus_macros::method(
        description = "Retrieve a single comment by UUID",
        params(id = "Comment UUID")
    )]
    async fn get(&self, id: String) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            let uuid = match Uuid::parse_str(&id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("invalid_id".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };
            match store.get_comment(uuid).await {
                Ok(Some(comment)) => yield TrakEvent::CommentDetail { comment },
                Ok(None) => yield TrakEvent::Error {
                    code: Some("not_found".into()),
                    message: format!("comment {id} not found"),
                },
                Err(e) => yield TrakEvent::Error {
                    code: Some("get_failed".into()),
                    message: e.to_string(),
                },
            }
        }
    }

    /// Edit a comment (only the author can edit)
    #[plexus_macros::method(
        description = "Edit a comment's body. Only the original author may edit.",
        params(
            id = "Comment UUID",
            body = "New comment body"
        )
    )]
    async fn update(
        &self,
        auth: &AuthContext,
        id: String,
        body: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let caller = author_from_auth(auth);
        stream! {
            let uuid = match Uuid::parse_str(&id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("invalid_id".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };
            if body.trim().is_empty() {
                yield TrakEvent::Error {
                    code: Some("empty_body".into()),
                    message: "comment body cannot be empty".into(),
                };
                return;
            }

            let existing = match store.get_comment(uuid).await {
                Ok(Some(c)) => c,
                Ok(None) => {
                    yield TrakEvent::Error {
                        code: Some("not_found".into()),
                        message: format!("comment {id} not found"),
                    };
                    return;
                }
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("get_failed".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };

            // Only the author can edit their own comment.
            if existing.author != caller {
                yield TrakEvent::Error {
                    code: Some("forbidden".into()),
                    message: "only the author may edit this comment".into(),
                };
                return;
            }

            if let Err(e) = store.update_comment(uuid, &body).await {
                yield TrakEvent::Error {
                    code: Some("update_failed".into()),
                    message: e.to_string(),
                };
                return;
            }

            // Re-fetch so we return the canonical updated row.
            match store.get_comment(uuid).await {
                Ok(Some(comment)) => yield TrakEvent::CommentUpdated { comment },
                Ok(None) => yield TrakEvent::Error {
                    code: Some("not_found".into()),
                    message: format!("comment {id} disappeared after update"),
                },
                Err(e) => yield TrakEvent::Error {
                    code: Some("get_failed".into()),
                    message: e.to_string(),
                },
            }
        }
    }

    /// Delete a comment (only the author can delete)
    #[plexus_macros::method(
        description = "Delete a comment. Only the original author may delete.",
        params(id = "Comment UUID")
    )]
    async fn delete(
        &self,
        auth: &AuthContext,
        id: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let caller = author_from_auth(auth);
        stream! {
            let uuid = match Uuid::parse_str(&id) {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("invalid_id".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };

            let existing = match store.get_comment(uuid).await {
                Ok(Some(c)) => c,
                Ok(None) => {
                    yield TrakEvent::Error {
                        code: Some("not_found".into()),
                        message: format!("comment {id} not found"),
                    };
                    return;
                }
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("get_failed".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };

            if existing.author != caller {
                yield TrakEvent::Error {
                    code: Some("forbidden".into()),
                    message: "only the author may delete this comment".into(),
                };
                return;
            }

            match store.delete_comment(uuid).await {
                Ok(true) => yield TrakEvent::CommentDeleted { id: uuid },
                Ok(false) => yield TrakEvent::Error {
                    code: Some("not_found".into()),
                    message: format!("comment {id} not found"),
                },
                Err(e) => yield TrakEvent::Error {
                    code: Some("delete_failed".into()),
                    message: e.to_string(),
                },
            }
        }
    }
}
