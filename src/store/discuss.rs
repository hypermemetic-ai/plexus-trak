use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

/// A comment on a facet (optionally a threaded reply to another comment).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Comment {
    pub id: Uuid,
    pub facet_id: Uuid,
    /// User ID of the author (from the auth context); "anonymous" if unauthenticated.
    pub author: String,
    /// Display name (from the auth context, if available).
    pub author_name: Option<String>,
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Set to true once a comment has been edited at least once.
    pub edited: bool,
    /// Parent comment ID for threaded replies (None for top-level).
    pub parent_comment_id: Option<Uuid>,
}

/// Discussion-specific queries sharing the same SQLite pool.
#[derive(Clone)]
pub struct DiscussStore {
    pool: SqlitePool,
}

impl DiscussStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create the comments table and indexes if they don't already exist.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS comments (
                id                TEXT PRIMARY KEY,
                facet_id          TEXT NOT NULL,
                author            TEXT NOT NULL,
                author_name       TEXT,
                body              TEXT NOT NULL,
                created_at        TEXT NOT NULL,
                updated_at        TEXT NOT NULL,
                edited            INTEGER NOT NULL DEFAULT 0,
                parent_comment_id TEXT
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_comments_facet ON comments(facet_id);")
            .execute(&self.pool)
            .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_comments_created ON comments(facet_id, created_at);",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_comment(&self, c: &Comment) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"INSERT INTO comments
               (id, facet_id, author, author_name, body, created_at, updated_at, edited, parent_comment_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(c.id.to_string())
        .bind(c.facet_id.to_string())
        .bind(&c.author)
        .bind(&c.author_name)
        .bind(&c.body)
        .bind(c.created_at.to_rfc3339())
        .bind(c.updated_at.to_rfc3339())
        .bind(if c.edited { 1_i64 } else { 0_i64 })
        .bind(c.parent_comment_id.map(|u| u.to_string()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_comment(&self, id: Uuid) -> Result<Option<Comment>, sqlx::Error> {
        let row = sqlx::query("SELECT * FROM comments WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(Self::row_to_comment(&r)?)),
            None => Ok(None),
        }
    }

    /// List comments on a facet, oldest first (chronological order, like a thread).
    pub async fn list_comments(
        &self,
        facet_id: Uuid,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Comment>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT * FROM comments WHERE facet_id = ? ORDER BY created_at ASC LIMIT ? OFFSET ?",
        )
        .bind(facet_id.to_string())
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(Self::row_to_comment).collect()
    }

    pub async fn count_comments(&self, facet_id: Uuid) -> Result<u32, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM comments WHERE facet_id = ?")
            .bind(facet_id.to_string())
            .fetch_one(&self.pool)
            .await?;
        let cnt: i64 = row.get("cnt");
        Ok(cnt as u32)
    }

    /// Update a comment's body, mark `edited = true`, bump `updated_at`.
    pub async fn update_comment(&self, id: Uuid, body: &str) -> Result<(), sqlx::Error> {
        let now = Utc::now();
        sqlx::query(
            "UPDATE comments SET body = ?, updated_at = ?, edited = 1 WHERE id = ?",
        )
        .bind(body)
        .bind(now.to_rfc3339())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete a comment. Returns true if it existed.
    pub async fn delete_comment(&self, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM comments WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    fn row_to_comment(row: &sqlx::sqlite::SqliteRow) -> Result<Comment, sqlx::Error> {
        let id_str: String = row.get("id");
        let facet_str: String = row.get("facet_id");
        let parent_str: Option<String> = row.get("parent_comment_id");
        let created_str: String = row.get("created_at");
        let updated_str: String = row.get("updated_at");
        let edited_int: i64 = row.get("edited");

        let parse_uuid = |s: &str| -> Result<Uuid, sqlx::Error> {
            Uuid::parse_str(s).map_err(|e| sqlx::Error::Decode(Box::new(BadUuid(e.to_string()))))
        };
        let parse_dt = |s: &str| -> Result<DateTime<Utc>, sqlx::Error> {
            DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| sqlx::Error::Decode(Box::new(BadDateTime(e.to_string()))))
        };

        Ok(Comment {
            id: parse_uuid(&id_str)?,
            facet_id: parse_uuid(&facet_str)?,
            author: row.get("author"),
            author_name: row.get("author_name"),
            body: row.get("body"),
            created_at: parse_dt(&created_str)?,
            updated_at: parse_dt(&updated_str)?,
            edited: edited_int != 0,
            parent_comment_id: parent_str.as_deref().map(parse_uuid).transpose()?,
        })
    }
}

#[derive(Debug)]
struct BadUuid(String);
impl std::fmt::Display for BadUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bad uuid: {}", self.0)
    }
}
impl std::error::Error for BadUuid {}

#[derive(Debug)]
struct BadDateTime(String);
impl std::fmt::Display for BadDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bad datetime: {}", self.0)
    }
}
impl std::error::Error for BadDateTime {}
