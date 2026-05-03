use chrono::{DateTime, Utc};
use sqlx::{Row, SqlitePool};

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
}
