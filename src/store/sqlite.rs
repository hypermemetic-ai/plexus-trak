use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::types::{Edge, EdgeKind, Facet};

use super::{Direction, FacetStore, StoreError};

/// SQLite-backed facet store.
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Expose the connection pool for shared use (e.g. IdentityStore).
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Open (or create) the database at `db_path` and run migrations.
    pub async fn new(db_path: &str) -> Result<Self, StoreError> {
        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(db_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| StoreError::Db(format!("cannot create db dir: {e}")))?;
        }

        let opts = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await?;

        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS facets (
                id          TEXT PRIMARY KEY,
                parent_id   TEXT,
                title       TEXT NOT NULL,
                body        TEXT,
                status      TEXT NOT NULL DEFAULT 'open',
                owner       TEXT NOT NULL DEFAULT 'anonymous',
                meta_json   TEXT NOT NULL DEFAULT '{}',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL,
                FOREIGN KEY (parent_id) REFERENCES facets(id) ON DELETE SET NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS edges (
                from_id     TEXT NOT NULL,
                to_id       TEXT NOT NULL,
                kind        TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                PRIMARY KEY (from_id, to_id, kind),
                FOREIGN KEY (from_id) REFERENCES facets(id) ON DELETE CASCADE,
                FOREIGN KEY (to_id)   REFERENCES facets(id) ON DELETE CASCADE
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        // FTS5 virtual table for full-text search on title + body.
        // CREATE VIRTUAL TABLE ... IF NOT EXISTS is supported by FTS5.
        sqlx::query(
            r#"
            CREATE VIRTUAL TABLE IF NOT EXISTS facets_fts USING fts5(
                id UNINDEXED,
                title,
                body,
                content='facets',
                content_rowid='rowid'
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Triggers to keep FTS in sync.
        // Use IF NOT EXISTS via a try — SQLite doesn't support IF NOT EXISTS
        // on triggers, so we just ignore the error if they already exist.
        let triggers = [
            r#"
            CREATE TRIGGER facets_ai AFTER INSERT ON facets BEGIN
                INSERT INTO facets_fts(id, title, body) VALUES (new.id, new.title, new.body);
            END;
            "#,
            r#"
            CREATE TRIGGER facets_ad AFTER DELETE ON facets BEGIN
                INSERT INTO facets_fts(facets_fts, id, title, body) VALUES('delete', old.id, old.title, old.body);
            END;
            "#,
            r#"
            CREATE TRIGGER facets_au AFTER UPDATE ON facets BEGIN
                INSERT INTO facets_fts(facets_fts, id, title, body) VALUES('delete', old.id, old.title, old.body);
                INSERT INTO facets_fts(id, title, body) VALUES (new.id, new.title, new.body);
            END;
            "#,
        ];
        for trigger in triggers {
            // Ignore "trigger already exists" errors.
            let _ = sqlx::query(trigger).execute(&self.pool).await;
        }

        // ── Identity tables ──────────────────────────────────────────
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id           TEXT PRIMARY KEY,
                username     TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                display_name TEXT,
                email        TEXT,
                roles        TEXT NOT NULL DEFAULT '[]',
                tenant       TEXT,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS api_keys (
                id           TEXT PRIMARY KEY,
                user_id      TEXT NOT NULL,
                name         TEXT NOT NULL,
                key_hash     TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                expires_at   TEXT,
                last_used_at TEXT
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id           TEXT PRIMARY KEY,
                user_id      TEXT NOT NULL,
                token_hash   TEXT NOT NULL,
                expires_at   TEXT NOT NULL,
                created_at   TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);",
        )
        .execute(&self.pool)
        .await?;

        // Index for parent_id lookups.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_facets_parent ON facets(parent_id);",
        )
        .execute(&self.pool)
        .await?;

        // Index for edge queries.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_id, kind);",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_id, kind);",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    fn row_to_facet(row: &sqlx::sqlite::SqliteRow) -> Result<Facet, StoreError> {
        let id_str: String = row.get("id");
        let parent_str: Option<String> = row.get("parent_id");
        let meta_json: String = row.get("meta_json");
        let created_str: String = row.get("created_at");
        let updated_str: String = row.get("updated_at");

        Ok(Facet {
            id: Uuid::parse_str(&id_str)
                .map_err(|e| StoreError::Db(format!("bad uuid: {e}")))?,
            parent_id: parent_str
                .as_deref()
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|e| StoreError::Db(format!("bad parent uuid: {e}")))?,
            title: row.get("title"),
            body: row.get("body"),
            status: row.get("status"),
            owner: row.get("owner"),
            meta: serde_json::from_str(&meta_json).unwrap_or_default(),
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| StoreError::Db(format!("bad created_at: {e}")))?,
            updated_at: DateTime::parse_from_rfc3339(&updated_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| StoreError::Db(format!("bad updated_at: {e}")))?,
        })
    }

    fn row_to_edge(row: &sqlx::sqlite::SqliteRow) -> Result<Edge, StoreError> {
        let from_str: String = row.get("from_id");
        let to_str: String = row.get("to_id");
        let kind_str: String = row.get("kind");
        let created_str: String = row.get("created_at");

        Ok(Edge {
            from_id: Uuid::parse_str(&from_str)
                .map_err(|e| StoreError::Db(format!("bad from uuid: {e}")))?,
            to_id: Uuid::parse_str(&to_str)
                .map_err(|e| StoreError::Db(format!("bad to uuid: {e}")))?,
            kind: kind_str
                .parse::<EdgeKind>()
                .map_err(|e| StoreError::Db(format!("bad edge kind: {e}")))?,
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| StoreError::Db(format!("bad created_at: {e}")))?,
        })
    }
}

#[async_trait]
impl FacetStore for SqliteStore {
    async fn create_facet(&self, facet: &Facet) -> Result<(), StoreError> {
        let meta_json =
            serde_json::to_string(&facet.meta).map_err(|e| StoreError::Db(e.to_string()))?;
        sqlx::query(
            r#"INSERT INTO facets (id, parent_id, title, body, status, owner, meta_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(facet.id.to_string())
        .bind(facet.parent_id.map(|u| u.to_string()))
        .bind(&facet.title)
        .bind(&facet.body)
        .bind(&facet.status)
        .bind(&facet.owner)
        .bind(&meta_json)
        .bind(facet.created_at.to_rfc3339())
        .bind(facet.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_facet(&self, id: Uuid) -> Result<Facet, StoreError> {
        let row = sqlx::query("SELECT * FROM facets WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound(id))?;
        Self::row_to_facet(&row)
    }

    async fn update_facet(&self, facet: &Facet) -> Result<(), StoreError> {
        let meta_json =
            serde_json::to_string(&facet.meta).map_err(|e| StoreError::Db(e.to_string()))?;
        let result = sqlx::query(
            r#"UPDATE facets SET title = ?, body = ?, status = ?, owner = ?, meta_json = ?, updated_at = ?
               WHERE id = ?"#,
        )
        .bind(&facet.title)
        .bind(&facet.body)
        .bind(&facet.status)
        .bind(&facet.owner)
        .bind(&meta_json)
        .bind(facet.updated_at.to_rfc3339())
        .bind(facet.id.to_string())
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound(facet.id));
        }
        Ok(())
    }

    async fn delete_facet(&self, id: Uuid) -> Result<(), StoreError> {
        let result = sqlx::query("DELETE FROM facets WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound(id));
        }
        Ok(())
    }

    async fn move_facet(&self, id: Uuid, new_parent: Option<Uuid>) -> Result<(), StoreError> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE facets SET parent_id = ?, updated_at = ? WHERE id = ?",
        )
        .bind(new_parent.map(|u| u.to_string()))
        .bind(now.to_rfc3339())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound(id));
        }
        Ok(())
    }

    async fn list_children(&self, parent_id: Option<Uuid>) -> Result<Vec<Facet>, StoreError> {
        let rows = match parent_id {
            Some(pid) => {
                sqlx::query("SELECT * FROM facets WHERE parent_id = ? ORDER BY created_at")
                    .bind(pid.to_string())
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query(
                    "SELECT * FROM facets WHERE parent_id IS NULL ORDER BY created_at",
                )
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.iter().map(Self::row_to_facet).collect()
    }

    async fn list_roots(&self) -> Result<Vec<Facet>, StoreError> {
        self.list_children(None).await
    }

    async fn get_ancestors(&self, id: Uuid) -> Result<Vec<Facet>, StoreError> {
        let rows = sqlx::query(
            r#"
            WITH RECURSIVE ancestors(id) AS (
                SELECT parent_id FROM facets WHERE id = ?
                UNION ALL
                SELECT f.parent_id FROM facets f JOIN ancestors a ON f.id = a.id
            )
            SELECT f.* FROM facets f JOIN ancestors a ON f.id = a.id
            WHERE a.id IS NOT NULL
            ORDER BY f.created_at
            "#,
        )
        .bind(id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(Self::row_to_facet).collect()
    }

    async fn get_subtree(&self, root_id: Uuid) -> Result<Vec<(Facet, u32)>, StoreError> {
        let rows = sqlx::query(
            r#"
            WITH RECURSIVE subtree(id, depth) AS (
                SELECT id, 0 AS depth FROM facets WHERE id = ?
                UNION ALL
                SELECT f.id, s.depth + 1
                FROM facets f JOIN subtree s ON f.parent_id = s.id
            )
            SELECT f.*, s.depth
            FROM facets f JOIN subtree s ON f.id = s.id
            ORDER BY s.depth, f.created_at
            "#,
        )
        .bind(root_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|row| {
                let depth: i32 = row.get("depth");
                Ok((Self::row_to_facet(row)?, depth as u32))
            })
            .collect()
    }

    async fn count_children(&self, parent_id: Option<Uuid>) -> Result<u32, StoreError> {
        let row = match parent_id {
            Some(pid) => {
                sqlx::query("SELECT COUNT(*) as cnt FROM facets WHERE parent_id = ?")
                    .bind(pid.to_string())
                    .fetch_one(&self.pool)
                    .await?
            }
            None => {
                sqlx::query(
                    "SELECT COUNT(*) as cnt FROM facets WHERE parent_id IS NULL",
                )
                .fetch_one(&self.pool)
                .await?
            }
        };
        let cnt: i32 = row.get("cnt");
        Ok(cnt as u32)
    }

    async fn add_edge(&self, edge: &Edge) -> Result<(), StoreError> {
        sqlx::query(
            r#"INSERT OR REPLACE INTO edges (from_id, to_id, kind, created_at)
               VALUES (?, ?, ?, ?)"#,
        )
        .bind(edge.from_id.to_string())
        .bind(edge.to_id.to_string())
        .bind(edge.kind.to_string())
        .bind(edge.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_edge(
        &self,
        from_id: Uuid,
        to_id: Uuid,
        kind: &EdgeKind,
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM edges WHERE from_id = ? AND to_id = ? AND kind = ?")
            .bind(from_id.to_string())
            .bind(to_id.to_string())
            .bind(kind.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_edges(
        &self,
        facet_id: Uuid,
        direction: Direction,
        kind: Option<&EdgeKind>,
    ) -> Result<Vec<Edge>, StoreError> {
        let id_str = facet_id.to_string();
        let kind_str = kind.map(|k| k.to_string());

        let rows = match (direction, &kind_str) {
            (Direction::Outgoing, Some(k)) => {
                sqlx::query("SELECT * FROM edges WHERE from_id = ? AND kind = ?")
                    .bind(&id_str)
                    .bind(k)
                    .fetch_all(&self.pool)
                    .await?
            }
            (Direction::Outgoing, None) => {
                sqlx::query("SELECT * FROM edges WHERE from_id = ?")
                    .bind(&id_str)
                    .fetch_all(&self.pool)
                    .await?
            }
            (Direction::Incoming, Some(k)) => {
                sqlx::query("SELECT * FROM edges WHERE to_id = ? AND kind = ?")
                    .bind(&id_str)
                    .bind(k)
                    .fetch_all(&self.pool)
                    .await?
            }
            (Direction::Incoming, None) => {
                sqlx::query("SELECT * FROM edges WHERE to_id = ?")
                    .bind(&id_str)
                    .fetch_all(&self.pool)
                    .await?
            }
            (Direction::Both, Some(k)) => {
                sqlx::query(
                    "SELECT * FROM edges WHERE (from_id = ? OR to_id = ?) AND kind = ?",
                )
                .bind(&id_str)
                .bind(&id_str)
                .bind(k)
                .fetch_all(&self.pool)
                .await?
            }
            (Direction::Both, None) => {
                sqlx::query("SELECT * FROM edges WHERE from_id = ? OR to_id = ?")
                    .bind(&id_str)
                    .bind(&id_str)
                    .fetch_all(&self.pool)
                    .await?
            }
        };

        rows.iter().map(Self::row_to_edge).collect()
    }

    async fn search(&self, query: &str) -> Result<Vec<(Facet, f64)>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT f.*, fts.rank
            FROM facets_fts fts
            JOIN facets f ON f.id = fts.id
            WHERE facets_fts MATCH ?
            ORDER BY fts.rank
            LIMIT 50
            "#,
        )
        .bind(query)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|row| {
                let rank: f64 = row.get("rank");
                Ok((Self::row_to_facet(row)?, -rank)) // FTS5 rank is negative; negate for score
            })
            .collect()
    }
}
