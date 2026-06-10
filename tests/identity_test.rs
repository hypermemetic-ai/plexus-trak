mod common;

use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use plexus_trak::store::identity::{ApiKeyRecord, IdentityStore, RefreshTokenRecord, UserRecord};
use plexus_trak::store::sqlite::SqliteStore;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::password_hash::rand_core::OsRng;
use argon2::Argon2;

// The LEGACY HS256 claim shape (mirrors the deprecated
// `plexus_trak::hubs::identity::Claims`) — kept here solely to mint
// old-world tokens and assert the UT-W3 validator REJECTS them.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyClaims {
    sub: String,
    username: String,
    roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    exp: usize,
    iat: usize,
}

/// Create a temporary store pair (SqliteStore + IdentityStore).
async fn temp_stores() -> (SqliteStore, IdentityStore, TempDir) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let sqlite = SqliteStore::new(db_path.to_str().unwrap()).await.unwrap();
    let identity = IdentityStore::new(sqlite.pool().clone());
    (sqlite, identity, dir)
}

fn make_user(username: &str, password: &str) -> UserRecord {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let now = Utc::now();

    UserRecord {
        id: uuid::Uuid::new_v4().to_string(),
        username: username.to_string(),
        password_hash,
        display_name: Some(format!("Test {username}")),
        email: Some(format!("{username}@test.com")),
        roles: vec!["user".to_string()],
        tenant: None,
        created_at: now,
        updated_at: now,
    }
}

fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

// ── User CRUD tests ────────────────────────────────────────────────

#[tokio::test]
async fn test_create_user() {
    let (_sqlite, store, _dir) = temp_stores().await;
    let user = make_user("alice", "password123");

    store.create_user(&user).await.unwrap();
    let got = store.get_user_by_username("alice").await.unwrap();

    assert_eq!(got.username, "alice");
    assert_eq!(got.display_name.as_deref(), Some("Test alice"));
    assert_eq!(got.email.as_deref(), Some("alice@test.com"));
    assert_eq!(got.roles, vec!["user"]);
}

#[tokio::test]
async fn test_create_duplicate_username() {
    let (_sqlite, store, _dir) = temp_stores().await;
    let user1 = make_user("bob", "pass1");
    let user2 = make_user("bob", "pass2");

    store.create_user(&user1).await.unwrap();
    let result = store.create_user(&user2).await;
    assert!(result.is_err(), "duplicate username should fail");
}

#[tokio::test]
async fn test_get_user_by_id() {
    let (_sqlite, store, _dir) = temp_stores().await;
    let user = make_user("carol", "pass");
    let id = user.id.clone();

    store.create_user(&user).await.unwrap();
    let got = store.get_user_by_id(&id).await.unwrap();
    assert_eq!(got.username, "carol");
}

#[tokio::test]
async fn test_verify_password() {
    let (_sqlite, store, _dir) = temp_stores().await;
    let user = make_user("dave", "correct_password");
    store.create_user(&user).await.unwrap();

    let got = store.get_user_by_username("dave").await.unwrap();

    // Correct password
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let parsed = PasswordHash::new(&got.password_hash).unwrap();
    assert!(Argon2::default()
        .verify_password(b"correct_password", &parsed)
        .is_ok());

    // Wrong password
    assert!(Argon2::default()
        .verify_password(b"wrong_password", &parsed)
        .is_err());
}

#[tokio::test]
async fn test_list_users() {
    let (_sqlite, store, _dir) = temp_stores().await;
    store.create_user(&make_user("u1", "p")).await.unwrap();
    store.create_user(&make_user("u2", "p")).await.unwrap();
    store.create_user(&make_user("u3", "p")).await.unwrap();

    let users = store.list_users().await.unwrap();
    assert_eq!(users.len(), 3);
}

// ── API key tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_api_key_create_and_find() {
    let (_sqlite, store, _dir) = temp_stores().await;
    let user = make_user("eve", "pass");
    store.create_user(&user).await.unwrap();

    let raw_key = "test-api-key-12345";
    let key_hash = sha256_hex(raw_key);
    let now = Utc::now();

    let record = ApiKeyRecord {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user.id.clone(),
        name: "test key".to_string(),
        key_hash: key_hash.clone(),
        created_at: now,
        expires_at: None,
        last_used_at: None,
    };

    store.create_api_key(&record).await.unwrap();

    let found = store
        .find_api_key_by_hash(&key_hash)
        .await
        .unwrap()
        .expect("should find key by hash");
    assert_eq!(found.user_id, user.id);
    assert_eq!(found.name, "test key");
}

#[tokio::test]
async fn test_api_key_not_found() {
    let (_sqlite, store, _dir) = temp_stores().await;
    let result = store
        .find_api_key_by_hash("nonexistent_hash")
        .await
        .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_api_key_list_and_delete() {
    let (_sqlite, store, _dir) = temp_stores().await;
    let user = make_user("frank", "pass");
    store.create_user(&user).await.unwrap();

    let now = Utc::now();
    for i in 0..3 {
        let record = ApiKeyRecord {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            name: format!("key-{i}"),
            key_hash: format!("hash-{i}"),
            created_at: now,
            expires_at: None,
            last_used_at: None,
        };
        store.create_api_key(&record).await.unwrap();
    }

    let keys = store.list_api_keys(&user.id).await.unwrap();
    assert_eq!(keys.len(), 3);

    // Delete one
    let deleted = store
        .delete_api_key(&keys[0].id, &user.id)
        .await
        .unwrap();
    assert!(deleted);

    let keys_after = store.list_api_keys(&user.id).await.unwrap();
    assert_eq!(keys_after.len(), 2);
}

#[tokio::test]
async fn test_api_key_touch() {
    let (_sqlite, store, _dir) = temp_stores().await;
    let user = make_user("grace", "pass");
    store.create_user(&user).await.unwrap();

    let key_id = uuid::Uuid::new_v4().to_string();
    let record = ApiKeyRecord {
        id: key_id.clone(),
        user_id: user.id.clone(),
        name: "touchable".to_string(),
        key_hash: "hash-touch".to_string(),
        created_at: Utc::now(),
        expires_at: None,
        last_used_at: None,
    };
    store.create_api_key(&record).await.unwrap();

    // Before touch, last_used_at is None
    let found = store
        .find_api_key_by_hash("hash-touch")
        .await
        .unwrap()
        .unwrap();
    assert!(found.last_used_at.is_none());

    // Touch
    store.touch_api_key(&key_id).await.unwrap();

    let found_after = store
        .find_api_key_by_hash("hash-touch")
        .await
        .unwrap()
        .unwrap();
    assert!(found_after.last_used_at.is_some());
}

// ── Refresh token tests ────────────────────────────────────────────

#[tokio::test]
async fn test_refresh_token_create_and_find() {
    let (_sqlite, store, _dir) = temp_stores().await;
    let user = make_user("henry", "pass");
    store.create_user(&user).await.unwrap();

    let raw_token = "refresh-token-abc123";
    let token_hash = sha256_hex(raw_token);
    let now = Utc::now();

    let record = RefreshTokenRecord {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user.id.clone(),
        token_hash: token_hash.clone(),
        expires_at: now + Duration::hours(24),
        created_at: now,
    };

    store.create_refresh_token(&record).await.unwrap();

    let found = store
        .find_refresh_token_by_hash(&token_hash)
        .await
        .unwrap()
        .expect("should find refresh token");
    assert_eq!(found.user_id, user.id);
}

#[tokio::test]
async fn test_refresh_token_delete() {
    let (_sqlite, store, _dir) = temp_stores().await;
    let user = make_user("iris", "pass");
    store.create_user(&user).await.unwrap();

    let token_hash = sha256_hex("some-token");
    let now = Utc::now();
    let token_id = uuid::Uuid::new_v4().to_string();

    let record = RefreshTokenRecord {
        id: token_id.clone(),
        user_id: user.id.clone(),
        token_hash: token_hash.clone(),
        expires_at: now + Duration::hours(24),
        created_at: now,
    };

    store.create_refresh_token(&record).await.unwrap();
    store.delete_refresh_token(&token_id).await.unwrap();

    let found = store
        .find_refresh_token_by_hash(&token_hash)
        .await
        .unwrap();
    assert!(found.is_none());
}

// ── TrakAuth (UT-W3: OIDC + API key validation) ────────────────────
//
// The HS256 path is GONE (issue 74103adf / UT-S01 D4 step 3). These
// tests pin the new contract: RS256 OIDC tokens against the configured
// issuer's JWKS validate; legacy HS256 tokens (even ones minted by the
// deprecated IdentityHub paths) do NOT; the API-key fallback is
// unchanged. Fixtures come from tests/common (no network).

use plexus_core::plexus::SessionValidator;

#[tokio::test]
async fn test_oidc_token_round_trip() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let auth = common::fixture_trak_auth(id_store);

    let token = common::mint_for("user-123", Some("org_acme"));
    let ctx = auth.validate(&token).await.expect("valid RS256 token must authenticate");

    assert_eq!(ctx.user_id, "user-123");
    assert!(ctx.has_role("user"));
    // UT-S01 D3 dual-key window: org_id AND the tenant_id alias.
    assert_eq!(ctx.get_metadata_string("org_id").as_deref(), Some("org_acme"));
    assert_eq!(ctx.get_metadata_string("tenant_id").as_deref(), Some("org_acme"));
    assert_eq!(ctx.get_metadata_string("auth_method").as_deref(), Some("oidc"));
    // The session_id quirk fix (UT-W3 deliverable 4): token-authed
    // contexts are *authenticated* — non-empty session id.
    assert!(!ctx.session_id.is_empty());
    assert!(ctx.is_authenticated());
}

#[tokio::test]
async fn test_legacy_hs256_token_rejected() {
    // The 74103adf forgery shape: an HS256 token signed with a local
    // shared secret. Pre-UT-W3 this validated; now it must NOT — there
    // is no dual-accept window (UT-S01 D4).
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let auth = common::fixture_trak_auth(id_store);

    let now = Utc::now();
    let claims = LegacyClaims {
        sub: "forged-user".to_string(),
        username: "admin".to_string(),
        roles: vec!["admin".to_string(), "superuser".to_string()],
        tenant: Some("victim-org".to_string()),
        exp: (now + Duration::days(30)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };
    let token = encode(
        &Header::default(), // HS256
        &claims,
        &EncodingKey::from_secret(b"any-local-secret"),
    )
    .unwrap();

    let ctx = auth.validate(&token).await;
    assert!(ctx.is_none(), "HS256 tokens must be rejected post-cutover");
}

#[tokio::test]
async fn test_oidc_expired_rejected() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let auth = common::fixture_trak_auth(id_store);

    let mut c = common::claims();
    c.insert("exp".into(), json!(common::now() - 10)); // zero leeway
    let token = common::mint(common::KID_1, common::KEY_1_PEM, c);

    assert!(auth.validate(&token).await.is_none(), "expired token must be rejected");
}

#[tokio::test]
async fn test_oidc_wrong_audience_rejected() {
    // Per-backend audience (UT-S01 D1): a token minted for another
    // backend must not replay against trak.
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let auth = common::fixture_trak_auth(id_store);

    let mut c = common::claims();
    c.insert("aud".into(), json!("plexus:hyperforge"));
    let token = common::mint(common::KID_1, common::KEY_1_PEM, c);

    assert!(auth.validate(&token).await.is_none(), "foreign-audience token must be rejected");
}

#[tokio::test]
async fn test_oidc_cookie_header_shape() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let auth = common::fixture_trak_auth(id_store);

    let token = common::mint_for("cookie-user", None);
    let cookie_header = format!("access_token={token}; other=value");

    let ctx = auth.validate(&cookie_header).await.expect("cookie-wrapped token must authenticate");
    assert_eq!(ctx.user_id, "cookie-user");
}

#[tokio::test]
async fn test_oidc_bare_token_shape() {
    // synapse `-t <jwt>` sends the bare token.
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let auth = common::fixture_trak_auth(id_store);

    let token = common::mint_for("bare-user", None);
    let ctx = auth.validate(&token).await.expect("bare token must authenticate");
    assert_eq!(ctx.user_id, "bare-user");
}

#[tokio::test]
async fn test_api_key_auth() {
    // API-key fallback retained unchanged through the cutover.
    let (_sqlite, id_store, _dir) = temp_stores().await;

    let user = make_user("api_user", "pass");
    id_store.create_user(&user).await.unwrap();

    let raw_key = "my-raw-api-key-for-testing";
    let key_hash = sha256_hex(raw_key);
    let now = Utc::now();
    let record = ApiKeyRecord {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user.id.clone(),
        name: "test".to_string(),
        key_hash,
        created_at: now,
        expires_at: None,
        last_used_at: None,
    };
    id_store.create_api_key(&record).await.unwrap();

    let auth = common::fixture_trak_auth(id_store);

    let ctx = auth.validate(raw_key).await;
    assert!(ctx.is_some(), "valid API key should authenticate");

    let ctx = ctx.unwrap();
    assert_eq!(ctx.user_id, user.id);
    assert_eq!(ctx.get_metadata_string("auth_method").as_deref(), Some("api_key"));
}

#[tokio::test]
async fn test_api_key_expired_rejected() {
    let (_sqlite, id_store, _dir) = temp_stores().await;

    let user = make_user("exp_user", "pass");
    id_store.create_user(&user).await.unwrap();

    let raw_key = "expired-api-key";
    let key_hash = sha256_hex(raw_key);
    let now = Utc::now();
    let record = ApiKeyRecord {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user.id.clone(),
        name: "expired".to_string(),
        key_hash,
        created_at: now - Duration::days(2),
        expires_at: Some(now - Duration::hours(1)), // expired
        last_used_at: None,
    };
    id_store.create_api_key(&record).await.unwrap();

    let auth = common::fixture_trak_auth(id_store);

    let ctx = auth.validate(raw_key).await;
    assert!(ctx.is_none(), "expired API key should be rejected");
}

#[tokio::test]
async fn test_invalid_token_string() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let auth = common::fixture_trak_auth(id_store);

    let ctx = auth.validate("not-a-valid-token-or-key").await;
    assert!(ctx.is_none(), "garbage token should return None");
}
