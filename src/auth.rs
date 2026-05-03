use async_trait::async_trait;
use jsonwebtoken::{decode, DecodingKey, Validation};
use plexus_core::plexus::{AuthContext, SessionValidator};
use sha2::{Digest, Sha256};

use crate::hubs::identity::Claims;
use crate::store::identity::IdentityStore;

/// Session validator for plexus-trak.
///
/// Attempts JWT validation first, then falls back to API key lookup.
pub struct TrakAuth {
    identity_store: IdentityStore,
    jwt_secret: Vec<u8>,
}

impl TrakAuth {
    pub fn new(identity_store: IdentityStore, jwt_secret: Vec<u8>) -> Self {
        Self {
            identity_store,
            jwt_secret,
        }
    }
}

#[async_trait]
impl SessionValidator for TrakAuth {
    async fn validate(&self, token: &str) -> Option<AuthContext> {
        // 1. Try JWT decode
        if let Some(ctx) = self.try_jwt(token) {
            return Some(ctx);
        }

        // 2. Try API key lookup
        self.try_api_key(token).await
    }
}

impl TrakAuth {
    fn try_jwt(&self, token: &str) -> Option<AuthContext> {
        let key = DecodingKey::from_secret(&self.jwt_secret);
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_required_spec_claims(&["sub", "exp", "iat"]);

        let data = decode::<Claims>(token, &key, &validation).ok()?;
        let claims = data.claims;

        let mut metadata = serde_json::Map::new();
        metadata.insert("username".into(), serde_json::Value::String(claims.username.clone()));
        if let Some(ref tenant) = claims.tenant {
            metadata.insert("tenant_id".into(), serde_json::Value::String(tenant.clone()));
        }

        Some(AuthContext::new(
            claims.sub,
            String::new(), // no session ID for JWT
            claims.roles,
            serde_json::Value::Object(metadata),
        ))
    }

    async fn try_api_key(&self, token: &str) -> Option<AuthContext> {
        let key_hash = hex::encode(Sha256::digest(token.as_bytes()));

        let record = self.identity_store.find_api_key_by_hash(&key_hash).await.ok()??;

        // Check expiry
        if let Some(expires) = record.expires_at {
            if expires < chrono::Utc::now() {
                return None;
            }
        }

        // Touch last_used_at (best effort)
        let _ = self.identity_store.touch_api_key(&record.id).await;

        // Look up user
        let user = self.identity_store.get_user_by_id(&record.user_id).await.ok()?;

        let mut metadata = serde_json::Map::new();
        metadata.insert("username".into(), serde_json::Value::String(user.username));
        metadata.insert(
            "auth_method".into(),
            serde_json::Value::String("api_key".into()),
        );
        if let Some(ref tenant) = user.tenant {
            metadata.insert("tenant_id".into(), serde_json::Value::String(tenant.clone()));
        }

        Some(AuthContext::new(
            user.id,
            String::new(),
            user.roles,
            serde_json::Value::Object(metadata),
        ))
    }
}
