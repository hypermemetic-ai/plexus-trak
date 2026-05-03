use std::sync::Arc;

use async_stream::stream;
use chrono::{Duration, Utc};
use futures::Stream;
use jsonwebtoken::{encode, EncodingKey, Header};
use plexus_core::plexus::AuthContext;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

use crate::events::TrakEvent;
use crate::store::identity::{ApiKeyRecord, IdentityStore, RefreshTokenRecord, UserRecord};

/// JWT claims for access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub exp: usize,
    pub iat: usize,
}

/// Access token TTL: 1 hour.
const ACCESS_TOKEN_TTL_SECS: i64 = 3600;
/// Refresh token TTL: 30 days.
const REFRESH_TOKEN_TTL_SECS: i64 = 30 * 24 * 3600;

/// IdentityHub — user registration, login, JWT tokens, API keys.
#[derive(Clone)]
pub struct IdentityHub {
    store: IdentityStore,
    jwt_secret: Arc<Vec<u8>>,
}

impl IdentityHub {
    pub fn new(store: IdentityStore, jwt_secret: Vec<u8>) -> Self {
        Self {
            store,
            jwt_secret: Arc::new(jwt_secret),
        }
    }

    /// Issue an access token JWT for the given user.
    fn issue_access_token(&self, user: &UserRecord) -> Result<(String, u64), String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(ACCESS_TOKEN_TTL_SECS);

        let claims = Claims {
            sub: user.id.clone(),
            username: user.username.clone(),
            roles: user.roles.clone(),
            tenant: user.tenant.clone(),
            exp: exp.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&self.jwt_secret),
        )
        .map_err(|e| format!("JWT encode error: {e}"))?;

        Ok((token, ACCESS_TOKEN_TTL_SECS as u64))
    }

    /// Generate a random hex string.
    fn random_hex(len: usize) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        hex::encode(bytes)
    }

    /// SHA-256 hash a string and return hex.
    fn sha256_hex(input: &str) -> String {
        hex::encode(Sha256::digest(input.as_bytes()))
    }
}

#[plexus_macros::activation(
    namespace = "identity",
    version = "0.1.0",
    description = "User registration, login, JWT tokens, and API keys",
    auth_posture = "mixed"
)]
impl IdentityHub {
    /// Register a new user
    #[plexus_macros::method(
        description = "Register a new user with username and password",
        params(
            username = "Username (unique)",
            password = "Password (will be hashed with Argon2id)",
            display_name = "Optional display name",
            email = "Optional email address",
            tenant = "Optional tenant/org identifier"
        )
    )]
    async fn register(
        &self,
        username: String,
        password: String,
        display_name: Option<String>,
        email: Option<String>,
        tenant: Option<String>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        stream! {
            // Hash password with Argon2id
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = match argon2.hash_password(password.as_bytes(), &salt) {
                Ok(h) => h.to_string(),
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("hash_failed".into()),
                        message: format!("password hashing failed: {e}"),
                    };
                    return;
                }
            };

            let now = Utc::now();
            let user_id = uuid::Uuid::new_v4().to_string();

            let user = UserRecord {
                id: user_id.clone(),
                username: username.clone(),
                password_hash,
                display_name,
                email,
                roles: vec!["user".into()],
                tenant,
                created_at: now,
                updated_at: now,
            };

            match store.create_user(&user).await {
                Ok(()) => yield TrakEvent::UserRegistered {
                    user_id,
                    username,
                },
                Err(e) => yield TrakEvent::Error {
                    code: Some("register_failed".into()),
                    message: e.to_string(),
                },
            }
        }
    }

    /// Log in with username and password
    #[plexus_macros::method(
        description = "Authenticate with username and password, receive JWT tokens",
        params(
            username = "Username",
            password = "Password"
        )
    )]
    async fn login(
        &self,
        username: String,
        password: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let jwt_secret = self.jwt_secret.clone();
        let self_clone = self.clone();
        stream! {
            // Look up user
            let user = match store.get_user_by_username(&username).await {
                Ok(u) => u,
                Err(_) => {
                    yield TrakEvent::Error {
                        code: Some("invalid_credentials".into()),
                        message: "invalid username or password".into(),
                    };
                    return;
                }
            };

            // Verify password
            let parsed_hash = match PasswordHash::new(&user.password_hash) {
                Ok(h) => h,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("hash_parse_failed".into()),
                        message: format!("stored hash invalid: {e}"),
                    };
                    return;
                }
            };

            if Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_err()
            {
                yield TrakEvent::Error {
                    code: Some("invalid_credentials".into()),
                    message: "invalid username or password".into(),
                };
                return;
            }

            // Issue access token
            let (access_token, expires_in) = match self_clone.issue_access_token(&user) {
                Ok(t) => t,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("token_error".into()),
                        message: e,
                    };
                    return;
                }
            };

            // Generate refresh token
            let raw_refresh = Self::random_hex(32); // 64-char hex
            let refresh_hash = Self::sha256_hex(&raw_refresh);
            let now = Utc::now();

            let token_record = RefreshTokenRecord {
                id: uuid::Uuid::new_v4().to_string(),
                user_id: user.id.clone(),
                token_hash: refresh_hash,
                expires_at: now + Duration::seconds(REFRESH_TOKEN_TTL_SECS),
                created_at: now,
            };

            if let Err(e) = store.create_refresh_token(&token_record).await {
                yield TrakEvent::Error {
                    code: Some("token_store_failed".into()),
                    message: e.to_string(),
                };
                return;
            }

            let _ = &jwt_secret; // keep Arc alive
            yield TrakEvent::LoginSuccess {
                access_token,
                refresh_token: raw_refresh,
                expires_in,
            };
        }
    }

    /// Refresh an access token using a refresh token
    #[plexus_macros::method(
        description = "Exchange a refresh token for a new access token",
        params(refresh_token = "The refresh token received at login")
    )]
    async fn refresh(
        &self,
        refresh_token: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let self_clone = self.clone();
        stream! {
            let token_hash = Self::sha256_hex(&refresh_token);

            // Find the refresh token
            let record = match store.find_refresh_token_by_hash(&token_hash).await {
                Ok(Some(r)) => r,
                Ok(None) => {
                    yield TrakEvent::Error {
                        code: Some("invalid_refresh_token".into()),
                        message: "refresh token not found or expired".into(),
                    };
                    return;
                }
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("token_lookup_failed".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };

            // Check expiry
            if record.expires_at < Utc::now() {
                let _ = store.delete_refresh_token(&record.id).await;
                yield TrakEvent::Error {
                    code: Some("refresh_token_expired".into()),
                    message: "refresh token has expired, please login again".into(),
                };
                return;
            }

            // Look up user
            let user = match store.get_user_by_id(&record.user_id).await {
                Ok(u) => u,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("user_lookup_failed".into()),
                        message: e.to_string(),
                    };
                    return;
                }
            };

            // Issue new access token
            let (access_token, expires_in) = match self_clone.issue_access_token(&user) {
                Ok(t) => t,
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("token_error".into()),
                        message: e,
                    };
                    return;
                }
            };

            yield TrakEvent::TokenRefreshed {
                access_token,
                expires_in,
            };
        }
    }

    /// Get the current user's info
    #[plexus_macros::method(
        description = "Return current user info from the auth context (requires authentication)"
    )]
    async fn me(
        &self,
        auth: &AuthContext,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let user_id = auth.user_id.clone();
        stream! {
            match store.get_user_by_id(&user_id).await {
                Ok(user) => {
                    yield TrakEvent::UserInfo {
                        user_id: user.id,
                        username: user.username,
                        display_name: user.display_name,
                        roles: user.roles,
                        tenant: user.tenant,
                    };
                }
                Err(e) => {
                    yield TrakEvent::Error {
                        code: Some("user_lookup_failed".into()),
                        message: e.to_string(),
                    };
                }
            }
        }
    }

    /// Create an API key for the current user
    #[plexus_macros::method(
        description = "Create an API key (requires authentication). The raw key is returned once.",
        params(
            name = "Human-readable name for the key",
            expires_in = "Optional TTL in seconds"
        )
    )]
    async fn create_api_key(
        &self,
        auth: &AuthContext,
        name: String,
        expires_in: Option<u64>,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let user_id = auth.user_id.clone();
        stream! {
            let raw_key = Self::random_hex(32); // 64-char hex
            let key_hash = Self::sha256_hex(&raw_key);
            let now = Utc::now();
            let key_id = uuid::Uuid::new_v4().to_string();

            let expires_at = expires_in.map(|secs| now + Duration::seconds(secs as i64));

            let record = ApiKeyRecord {
                id: key_id.clone(),
                user_id,
                name: name.clone(),
                key_hash,
                created_at: now,
                expires_at,
                last_used_at: None,
            };

            match store.create_api_key(&record).await {
                Ok(()) => yield TrakEvent::ApiKeyCreated {
                    key_id,
                    name,
                    key: raw_key,
                },
                Err(e) => yield TrakEvent::Error {
                    code: Some("api_key_create_failed".into()),
                    message: e.to_string(),
                },
            }
        }
    }

    /// Revoke an API key
    #[plexus_macros::method(
        description = "Revoke (delete) an API key by ID (requires authentication)",
        params(key_id = "The API key ID to revoke")
    )]
    async fn revoke_api_key(
        &self,
        auth: &AuthContext,
        key_id: String,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let user_id = auth.user_id.clone();
        stream! {
            match store.delete_api_key(&key_id, &user_id).await {
                Ok(true) => yield TrakEvent::ApiKeyRevoked { key_id },
                Ok(false) => yield TrakEvent::Error {
                    code: Some("not_found".into()),
                    message: format!("API key {key_id} not found or not owned by you"),
                },
                Err(e) => yield TrakEvent::Error {
                    code: Some("revoke_failed".into()),
                    message: e.to_string(),
                },
            }
        }
    }

    /// List API keys for the current user
    #[plexus_macros::method(
        description = "List API keys for the current user (requires authentication). Raw keys are never shown."
    )]
    async fn list_api_keys(
        &self,
        auth: &AuthContext,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let user_id = auth.user_id.clone();
        stream! {
            match store.list_api_keys(&user_id).await {
                Ok(keys) => {
                    let key_list: Vec<serde_json::Value> = keys
                        .iter()
                        .map(|k| {
                            serde_json::json!({
                                "id": k.id,
                                "name": k.name,
                                "created_at": k.created_at.to_rfc3339(),
                                "expires_at": k.expires_at.map(|d| d.to_rfc3339()),
                                "last_used_at": k.last_used_at.map(|d| d.to_rfc3339()),
                            })
                        })
                        .collect();
                    yield TrakEvent::ApiKeyList { keys: key_list };
                }
                Err(e) => yield TrakEvent::Error {
                    code: Some("list_failed".into()),
                    message: e.to_string(),
                },
            }
        }
    }

    /// List all users (admin only)
    #[plexus_macros::method(
        description = "List all registered users (requires admin role)"
    )]
    async fn list_users(
        &self,
        auth: &AuthContext,
    ) -> impl Stream<Item = TrakEvent> + Send + 'static {
        let store = self.store.clone();
        let has_admin = auth.has_role("admin");
        stream! {
            if !has_admin {
                yield TrakEvent::Error {
                    code: Some("forbidden".into()),
                    message: "admin role required".into(),
                };
                return;
            }

            match store.list_users().await {
                Ok(users) => {
                    let user_list: Vec<serde_json::Value> = users
                        .iter()
                        .map(|u| {
                            serde_json::json!({
                                "id": u.id,
                                "username": u.username,
                                "display_name": u.display_name,
                                "email": u.email,
                                "roles": u.roles,
                                "tenant": u.tenant,
                                "created_at": u.created_at.to_rfc3339(),
                            })
                        })
                        .collect();
                    yield TrakEvent::UserList { users: user_list };
                }
                Err(e) => yield TrakEvent::Error {
                    code: Some("list_failed".into()),
                    message: e.to_string(),
                },
            }
        }
    }
}
