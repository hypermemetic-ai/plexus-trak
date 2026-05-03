use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use plexus_trak::auth::TrakAuth;
use plexus_trak::store::identity::{ApiKeyRecord, IdentityStore, RefreshTokenRecord, UserRecord};
use plexus_trak::store::sqlite::SqliteStore;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::password_hash::rand_core::OsRng;
use argon2::Argon2;

// Re-use the Claims struct from the identity hub
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
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

// ── TrakAuth (JWT + API key validation) ────────────────────────────

#[tokio::test]
async fn test_jwt_validation() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let secret = b"test-jwt-secret-key".to_vec();
    let auth = TrakAuth::new(id_store, secret.clone());

    let now = Utc::now();
    let claims = Claims {
        sub: "user-123".to_string(),
        username: "testuser".to_string(),
        roles: vec!["user".to_string()],
        tenant: None,
        exp: (now + Duration::hours(1)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret),
    )
    .unwrap();

    use plexus_core::plexus::SessionValidator;
    let ctx = auth.validate(&token).await;
    assert!(ctx.is_some(), "valid JWT should authenticate");

    let ctx = ctx.unwrap();
    assert_eq!(ctx.user_id, "user-123");
}

#[tokio::test]
async fn test_jwt_expired() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let secret = b"test-jwt-secret-key".to_vec();
    let auth = TrakAuth::new(id_store, secret.clone());

    let now = Utc::now();
    let claims = Claims {
        sub: "user-456".to_string(),
        username: "expired_user".to_string(),
        roles: vec!["user".to_string()],
        tenant: None,
        exp: (now - Duration::hours(1)).timestamp() as usize, // expired
        iat: (now - Duration::hours(2)).timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret),
    )
    .unwrap();

    use plexus_core::plexus::SessionValidator;
    let ctx = auth.validate(&token).await;
    assert!(ctx.is_none(), "expired JWT should not authenticate");
}

#[tokio::test]
async fn test_jwt_wrong_secret() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let secret = b"correct-secret".to_vec();
    let wrong_secret = b"wrong-secret".to_vec();
    let auth = TrakAuth::new(id_store, secret);

    let now = Utc::now();
    let claims = Claims {
        sub: "user-789".to_string(),
        username: "wrong_secret_user".to_string(),
        roles: vec!["user".to_string()],
        tenant: None,
        exp: (now + Duration::hours(1)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&wrong_secret),
    )
    .unwrap();

    use plexus_core::plexus::SessionValidator;
    let ctx = auth.validate(&token).await;
    assert!(ctx.is_none(), "JWT with wrong secret should not authenticate");
}

#[tokio::test]
async fn test_api_key_auth() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let secret = b"jwt-secret".to_vec();

    // Create a user
    let user = make_user("api_user", "pass");
    id_store.create_user(&user).await.unwrap();

    // Create an API key
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

    let auth = TrakAuth::new(id_store, secret);

    use plexus_core::plexus::SessionValidator;
    let ctx = auth.validate(raw_key).await;
    assert!(ctx.is_some(), "valid API key should authenticate");

    let ctx = ctx.unwrap();
    assert_eq!(ctx.user_id, user.id);
}

#[tokio::test]
async fn test_api_key_expired_rejected() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let secret = b"jwt-secret".to_vec();

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

    let auth = TrakAuth::new(id_store, secret);

    use plexus_core::plexus::SessionValidator;
    let ctx = auth.validate(raw_key).await;
    assert!(ctx.is_none(), "expired API key should be rejected");
}

#[tokio::test]
async fn test_cookie_parsing() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let secret = b"cookie-secret".to_vec();
    let auth = TrakAuth::new(id_store, secret.clone());

    let now = Utc::now();
    let claims = Claims {
        sub: "cookie-user".to_string(),
        username: "cookieuser".to_string(),
        roles: vec!["user".to_string()],
        tenant: None,
        exp: (now + Duration::hours(1)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret),
    )
    .unwrap();

    // Wrap in cookie format
    let cookie_header = format!("access_token={token}; other=value");

    use plexus_core::plexus::SessionValidator;
    let ctx = auth.validate(&cookie_header).await;
    assert!(ctx.is_some(), "JWT in cookie header should authenticate");
    assert_eq!(ctx.unwrap().user_id, "cookie-user");
}

#[tokio::test]
async fn test_bare_token() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let secret = b"bare-secret".to_vec();
    let auth = TrakAuth::new(id_store, secret.clone());

    let now = Utc::now();
    let claims = Claims {
        sub: "bare-user".to_string(),
        username: "bareuser".to_string(),
        roles: vec!["user".to_string()],
        tenant: None,
        exp: (now + Duration::hours(1)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret),
    )
    .unwrap();

    // Pass raw token without cookie prefix
    use plexus_core::plexus::SessionValidator;
    let ctx = auth.validate(&token).await;
    assert!(ctx.is_some(), "bare JWT token should authenticate");
    assert_eq!(ctx.unwrap().user_id, "bare-user");
}

#[tokio::test]
async fn test_jwt_with_tenant() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let secret = b"tenant-secret".to_vec();
    let auth = TrakAuth::new(id_store, secret.clone());

    let now = Utc::now();
    let claims = Claims {
        sub: "tenant-user".to_string(),
        username: "tenantuser".to_string(),
        roles: vec!["user".to_string(), "admin".to_string()],
        tenant: Some("acme-corp".to_string()),
        exp: (now + Duration::hours(1)).timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret),
    )
    .unwrap();

    use plexus_core::plexus::SessionValidator;
    let ctx = auth.validate(&token).await.expect("should validate");
    assert_eq!(ctx.user_id, "tenant-user");
    assert!(ctx.has_role("admin"));
    assert!(ctx.has_role("user"));
}

#[tokio::test]
async fn test_invalid_token_string() {
    let (_sqlite, id_store, _dir) = temp_stores().await;
    let secret = b"secret".to_vec();
    let auth = TrakAuth::new(id_store, secret);

    use plexus_core::plexus::SessionValidator;
    let ctx = auth.validate("not-a-valid-token-or-key").await;
    assert!(ctx.is_none(), "garbage token should return None");
}
