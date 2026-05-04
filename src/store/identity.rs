use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use super::StoreError;

/// User record from the database.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub tenant: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// API key record (without the raw key).
#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub key_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Refresh token record.
#[derive(Debug, Clone)]
pub struct RefreshTokenRecord {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// SRP identity — zero-knowledge auth record.
///
/// The server stores only `salt` and `verifier`. The password is never
/// transmitted or stored. `verifier = g^x mod N` where `x = H(salt, password)`.
#[derive(Debug, Clone)]
pub struct SrpIdentity {
    pub id: Uuid,
    pub display_name: Option<String>,
    pub salt: Vec<u8>,
    pub verifier: Vec<u8>,
    pub roles: Vec<String>,
    pub tenant: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_auth_at: Option<DateTime<Utc>>,
}

/// SRP handshake session — short-lived (5 min TTL), single-use.
///
/// Created on `srp_init`, consumed by `srp_verify`. Holds the server's
/// ephemeral keypair plus the client's public ephemeral.
#[derive(Debug, Clone)]
pub struct SrpSession {
    /// Hex-encoded session ID.
    pub session_id: String,
    pub identity_id: Uuid,
    /// Server's ephemeral private value `b`.
    pub server_secret: Vec<u8>,
    /// Server's ephemeral public value `B`.
    pub server_public: Vec<u8>,
    /// Client's ephemeral public value `A`.
    pub client_public: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

/// Identity-specific queries sharing the same SQLite pool.
#[derive(Clone)]
pub struct IdentityStore {
    pool: SqlitePool,
}

impl IdentityStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    // ── Users ──────────────────────────────────────────────────────

    pub async fn create_user(&self, user: &UserRecord) -> Result<(), StoreError> {
        let roles_json =
            serde_json::to_string(&user.roles).map_err(|e| StoreError::Db(e.to_string()))?;
        sqlx::query(
            r#"INSERT INTO users (id, username, password_hash, display_name, email, roles, tenant, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(&user.display_name)
        .bind(&user.email)
        .bind(&roles_json)
        .bind(&user.tenant)
        .bind(user.created_at.to_rfc3339())
        .bind(user.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<UserRecord, StoreError> {
        let row = sqlx::query("SELECT * FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| StoreError::Db(format!("user not found: {username}")))?;
        Self::row_to_user(&row)
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<UserRecord, StoreError> {
        let row = sqlx::query("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| StoreError::Db(format!("user not found: {id}")))?;
        Self::row_to_user(&row)
    }

    pub async fn list_users(&self) -> Result<Vec<UserRecord>, StoreError> {
        let rows = sqlx::query("SELECT * FROM users ORDER BY created_at")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(Self::row_to_user).collect()
    }

    fn row_to_user(row: &sqlx::sqlite::SqliteRow) -> Result<UserRecord, StoreError> {
        let roles_str: String = row.get("roles");
        let created_str: String = row.get("created_at");
        let updated_str: String = row.get("updated_at");

        Ok(UserRecord {
            id: row.get("id"),
            username: row.get("username"),
            password_hash: row.get("password_hash"),
            display_name: row.get("display_name"),
            email: row.get("email"),
            roles: serde_json::from_str(&roles_str).unwrap_or_default(),
            tenant: row.get("tenant"),
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| StoreError::Db(format!("bad created_at: {e}")))?,
            updated_at: DateTime::parse_from_rfc3339(&updated_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| StoreError::Db(format!("bad updated_at: {e}")))?,
        })
    }

    // ── API keys ───────────────────────────────────────────────────

    pub async fn create_api_key(&self, key: &ApiKeyRecord) -> Result<(), StoreError> {
        sqlx::query(
            r#"INSERT INTO api_keys (id, user_id, name, key_hash, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&key.id)
        .bind(&key.user_id)
        .bind(&key.name)
        .bind(&key.key_hash)
        .bind(key.created_at.to_rfc3339())
        .bind(key.expires_at.map(|d| d.to_rfc3339()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_api_key(&self, key_id: &str, user_id: &str) -> Result<bool, StoreError> {
        let result =
            sqlx::query("DELETE FROM api_keys WHERE id = ? AND user_id = ?")
                .bind(key_id)
                .bind(user_id)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_api_keys(&self, user_id: &str) -> Result<Vec<ApiKeyRecord>, StoreError> {
        let rows =
            sqlx::query("SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await?;
        rows.iter().map(Self::row_to_api_key).collect()
    }

    /// Look up an API key by its hash. Returns the record if found.
    pub async fn find_api_key_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<ApiKeyRecord>, StoreError> {
        let row = sqlx::query("SELECT * FROM api_keys WHERE key_hash = ?")
            .bind(key_hash)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(Self::row_to_api_key(&r)?)),
            None => Ok(None),
        }
    }

    /// Update `last_used_at` for an API key.
    pub async fn touch_api_key(&self, key_id: &str) -> Result<(), StoreError> {
        let now = Utc::now();
        sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
            .bind(now.to_rfc3339())
            .bind(key_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn row_to_api_key(row: &sqlx::sqlite::SqliteRow) -> Result<ApiKeyRecord, StoreError> {
        let created_str: String = row.get("created_at");
        let expires_str: Option<String> = row.get("expires_at");
        let used_str: Option<String> = row.get("last_used_at");

        Ok(ApiKeyRecord {
            id: row.get("id"),
            user_id: row.get("user_id"),
            name: row.get("name"),
            key_hash: row.get("key_hash"),
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| StoreError::Db(format!("bad created_at: {e}")))?,
            expires_at: expires_str
                .as_deref()
                .map(DateTime::parse_from_rfc3339)
                .transpose()
                .map_err(|e| StoreError::Db(format!("bad expires_at: {e}")))?
                .map(|dt| dt.with_timezone(&Utc)),
            last_used_at: used_str
                .as_deref()
                .map(DateTime::parse_from_rfc3339)
                .transpose()
                .map_err(|e| StoreError::Db(format!("bad last_used_at: {e}")))?
                .map(|dt| dt.with_timezone(&Utc)),
        })
    }

    // ── Refresh tokens ─────────────────────────────────────────────

    pub async fn create_refresh_token(
        &self,
        token: &RefreshTokenRecord,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?)"#,
        )
        .bind(&token.id)
        .bind(&token.user_id)
        .bind(&token.token_hash)
        .bind(token.expires_at.to_rfc3339())
        .bind(token.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find a refresh token by its hash.
    pub async fn find_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenRecord>, StoreError> {
        let row =
            sqlx::query("SELECT * FROM refresh_tokens WHERE token_hash = ?")
                .bind(token_hash)
                .fetch_optional(&self.pool)
                .await?;
        match row {
            Some(r) => Ok(Some(Self::row_to_refresh_token(&r)?)),
            None => Ok(None),
        }
    }

    /// Delete a refresh token (used on rotation).
    pub async fn delete_refresh_token(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM refresh_tokens WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete all refresh tokens for a user.
    #[allow(dead_code)]
    pub async fn delete_user_refresh_tokens(&self, user_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn row_to_refresh_token(
        row: &sqlx::sqlite::SqliteRow,
    ) -> Result<RefreshTokenRecord, StoreError> {
        let expires_str: String = row.get("expires_at");
        let created_str: String = row.get("created_at");

        Ok(RefreshTokenRecord {
            id: row.get("id"),
            user_id: row.get("user_id"),
            token_hash: row.get("token_hash"),
            expires_at: DateTime::parse_from_rfc3339(&expires_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| StoreError::Db(format!("bad expires_at: {e}")))?,
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| StoreError::Db(format!("bad created_at: {e}")))?,
        })
    }

    // ── SRP identities ─────────────────────────────────────────────

    pub async fn create_srp_identity(&self, identity: &SrpIdentity) -> Result<(), StoreError> {
        let roles_json = serde_json::to_string(&identity.roles)
            .map_err(|e| StoreError::Db(e.to_string()))?;
        sqlx::query(
            r#"INSERT INTO srp_identities (id, display_name, salt, verifier, roles, tenant, created_at, last_auth_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(identity.id.to_string())
        .bind(&identity.display_name)
        .bind(&identity.salt)
        .bind(&identity.verifier)
        .bind(&roles_json)
        .bind(&identity.tenant)
        .bind(identity.created_at.to_rfc3339())
        .bind(identity.last_auth_at.map(|d| d.to_rfc3339()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_srp_identity(&self, id: Uuid) -> Result<Option<SrpIdentity>, StoreError> {
        let row = sqlx::query("SELECT * FROM srp_identities WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(Self::row_to_srp_identity(&r)?)),
            None => Ok(None),
        }
    }

    /// Update `last_auth_at` for a successful SRP verify.
    pub async fn touch_srp_identity(&self, id: Uuid) -> Result<(), StoreError> {
        let now = Utc::now();
        sqlx::query("UPDATE srp_identities SET last_auth_at = ? WHERE id = ?")
            .bind(now.to_rfc3339())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn row_to_srp_identity(row: &sqlx::sqlite::SqliteRow) -> Result<SrpIdentity, StoreError> {
        let id_str: String = row.get("id");
        let roles_str: String = row.get("roles");
        let created_str: String = row.get("created_at");
        let last_auth_str: Option<String> = row.get("last_auth_at");

        Ok(SrpIdentity {
            id: Uuid::parse_str(&id_str)
                .map_err(|e| StoreError::Db(format!("bad uuid: {e}")))?,
            display_name: row.get("display_name"),
            salt: row.get("salt"),
            verifier: row.get("verifier"),
            roles: serde_json::from_str(&roles_str).unwrap_or_default(),
            tenant: row.get("tenant"),
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| StoreError::Db(format!("bad created_at: {e}")))?,
            last_auth_at: last_auth_str
                .as_deref()
                .map(DateTime::parse_from_rfc3339)
                .transpose()
                .map_err(|e| StoreError::Db(format!("bad last_auth_at: {e}")))?
                .map(|dt| dt.with_timezone(&Utc)),
        })
    }

    // ── SRP sessions ───────────────────────────────────────────────

    pub async fn create_srp_session(&self, session: &SrpSession) -> Result<(), StoreError> {
        sqlx::query(
            r#"INSERT INTO srp_sessions (session_id, identity_id, server_secret, server_public, client_public, created_at)
               VALUES (?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&session.session_id)
        .bind(session.identity_id.to_string())
        .bind(&session.server_secret)
        .bind(&session.server_public)
        .bind(&session.client_public)
        .bind(session.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_srp_session(
        &self,
        session_id: &str,
    ) -> Result<Option<SrpSession>, StoreError> {
        let row = sqlx::query("SELECT * FROM srp_sessions WHERE session_id = ?")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(Self::row_to_srp_session(&r)?)),
            None => Ok(None),
        }
    }

    pub async fn delete_srp_session(&self, session_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM srp_sessions WHERE session_id = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete sessions older than `ttl_seconds`. Returns count removed.
    pub async fn cleanup_expired_srp_sessions(
        &self,
        ttl_seconds: i64,
    ) -> Result<u32, StoreError> {
        let cutoff = Utc::now() - chrono::Duration::seconds(ttl_seconds);
        let result = sqlx::query("DELETE FROM srp_sessions WHERE created_at < ?")
            .bind(cutoff.to_rfc3339())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() as u32)
    }

    fn row_to_srp_session(row: &sqlx::sqlite::SqliteRow) -> Result<SrpSession, StoreError> {
        let identity_str: String = row.get("identity_id");
        let created_str: String = row.get("created_at");

        Ok(SrpSession {
            session_id: row.get("session_id"),
            identity_id: Uuid::parse_str(&identity_str)
                .map_err(|e| StoreError::Db(format!("bad identity uuid: {e}")))?,
            server_secret: row.get("server_secret"),
            server_public: row.get("server_public"),
            client_public: row.get("client_public"),
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| StoreError::Db(format!("bad created_at: {e}")))?,
        })
    }
}
