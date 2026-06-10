//! `TrakAuth` — trak's `SessionValidator`: OIDC tokens first, API keys second.
//!
//! **UT-W3 (wave 3, UT-S01 D4 step 3): the HS256 path is GONE.** The old
//! `try_jwt` decoded tokens with `DecodingKey::from_secret(&jwt_secret)` —
//! the same world-readable shared secret that signed them. Any local
//! process that could read `~/Library/Application Support/trak/jwt_secret`
//! could mint admin / cross-tenant tokens indistinguishable from real
//! logins (issue 74103adf, demonstrated live). Validation now routes
//! through [`plexus_auth_core_ut1::oidc::OidcSessionValidator`]:
//!
//! 1. issuer config → OIDC discovery → JWKS (cached per AUTH-8 policy);
//! 2. RS256 signature by `kid` + `iss`/`aud`/`exp`/`iat` with zero leeway;
//! 3. sealed `VerifiedUser` → `AuthContext` carrying `org_id` (and the
//!    `tenant_id` deprecation alias), `username`, `roles`,
//!    `auth_method: "oidc"`, and a REAL `session_id` (`sid` claim, else
//!    `jti`, else the token's signature segment) — closing the
//!    "`is_authenticated()` false for token-authed callers" quirk the old
//!    `try_jwt` had (it minted `session_id = ""`).
//!
//! `jwt_secret` no longer appears anywhere in the validation path. The
//! IdentityHub's HS256 *mint* paths still compile (marked deprecated, see
//! `src/hubs/identity.rs`) but tokens they mint are NOT accepted here —
//! no dual-accept window (UT-S01 D4): old HS256 access tokens drain within
//! their 1 h TTL; clients re-login against plexus-idp.
//!
//! The **API-key fallback is retained unchanged** — per the UT-S01
//! interchangeability bar, API keys sit *beside* the OIDC surface in this
//! chain, they do not gate interchangeability.

use async_trait::async_trait;
use plexus_core::plexus::{AuthContext, SessionValidator};
// TODO: s/plexus_auth_core_ut1/plexus_auth_core/ once feature/UT-1-tenancy-oidc merges.
use plexus_auth_core_ut1::oidc::{
    Audience, OidcConfig, OidcSessionValidator, OidcValidator,
};
use plexus_auth_core_ut1::{IssuerUrl, SessionValidator as Ut1SessionValidator};
use sha2::{Digest, Sha256};

use crate::store::identity::IdentityStore;

/// Default issuer: the local plexus-idp OIDC surface (UT-2's default HTTP
/// port). Override with `--oidc-issuer` / `TRAK_OIDC_ISSUER`.
pub const DEFAULT_OIDC_ISSUER: &str = "http://localhost:4461";

/// Default audience: trak's per-backend API identifier (UT-S01 D1 — a
/// token minted for another backend must not replay here). Override with
/// `--oidc-audience` / `TRAK_OIDC_AUDIENCE`.
pub const DEFAULT_OIDC_AUDIENCE: &str = "plexus:trak";

/// Build the [`OidcConfig`] for trak from issuer/audience strings
/// (typically CLI flags or the `TRAK_OIDC_ISSUER` / `TRAK_OIDC_AUDIENCE`
/// environment, with the defaults above).
pub fn oidc_config(issuer: &str, audience: &str) -> anyhow::Result<OidcConfig> {
    let issuer_url: url::Url = issuer
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid OIDC issuer URL {issuer:?}: {e}"))?;
    let issuer = IssuerUrl::try_new(issuer_url)
        .map_err(|e| anyhow::anyhow!("invalid OIDC issuer: {e}"))?;
    let audience = Audience::try_new(audience)
        .map_err(|e| anyhow::anyhow!("invalid OIDC audience: {e}"))?;
    Ok(OidcConfig::new(issuer, audience))
}

/// UT-W3-MIRROR: field-for-field bridge from the UT-1 branch's
/// `AuthContext` (what `OidcSessionValidator` mints) to the handlers'
/// `plexus_core::plexus::AuthContext`. Identical structs, distinct crate
/// identities while UT-1 is unmerged. DELETE together with the
/// ut1-auth-core shim once feature/UT-1-tenancy-oidc merges.
fn mirror_auth_back(ctx: plexus_auth_core_ut1::AuthContext) -> AuthContext {
    AuthContext::new(ctx.user_id, ctx.session_id, ctx.roles, ctx.metadata)
}

/// Session validator for plexus-trak.
///
/// Attempts OIDC validation first (RS256 against the configured issuer's
/// JWKS), then falls back to API key lookup. Both produce the handlers'
/// `AuthContext`; all rejections collapse to `None` (anonymous) — no
/// oracle about *why* a credential was rejected.
pub struct TrakAuth {
    identity_store: IdentityStore,
    oidc: OidcSessionValidator,
}

impl TrakAuth {
    /// Build with the production (reqwest) discovery/JWKS fetcher.
    pub fn new(identity_store: IdentityStore, config: OidcConfig) -> Self {
        Self::with_validator(identity_store, OidcValidator::new(config))
    }

    /// Build over an injected [`OidcValidator`] (tests supply a fixture
    /// fetcher; production uses [`TrakAuth::new`]).
    pub fn with_validator(identity_store: IdentityStore, validator: OidcValidator) -> Self {
        Self {
            identity_store,
            oidc: OidcSessionValidator::new(validator),
        }
    }
}

#[async_trait]
impl SessionValidator for TrakAuth {
    async fn validate(&self, cookie_header: &str) -> Option<AuthContext> {
        // 1. OIDC (RS256 + kid + iss/aud/exp, locally against the cached
        //    JWKS). `OidcSessionValidator` handles both the Cookie-header
        //    shape (`access_token=...; other=...`) and the bare-token
        //    shape (synapse `-t <jwt>`), matching the old extractor.
        if let Some(ctx) = self.oidc.validate(cookie_header).await {
            // UT-W3-MIRROR: bridge UT-1's AuthContext to the handlers'.
            return Some(mirror_auth_back(ctx));
        }

        // 2. API key lookup (retained unchanged — sits beside the OIDC
        //    surface per the UT-S01 interchangeability bar).
        let token = extract_token_from_cookies(cookie_header);
        self.try_api_key(token).await
    }
}

/// Parse cookie header for `access_token` value, or return the raw string
/// if it looks like a bare token (no `=` sign). (The OIDC path has its own
/// equivalent extractor inside `OidcSessionValidator`; this one feeds the
/// API-key fallback.)
fn extract_token_from_cookies(cookie_header: &str) -> &str {
    // If it doesn't contain '=', treat as a raw token
    if !cookie_header.contains('=') {
        return cookie_header.trim();
    }
    // Parse cookie pairs
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("access_token=") {
            return val.trim();
        }
    }
    // Fallback: try the whole string as a token
    cookie_header.trim()
}

impl TrakAuth {
    /// API-key fallback (unchanged from pre-UT-W3): SHA-256 the presented
    /// token, look it up in the `api_keys` table, enforce expiry, touch
    /// `last_used_at`, and build the AuthContext from the owning user row.
    ///
    /// NOTE (pre-existing, unchanged by UT-W3): API-key contexts carry an
    /// empty `session_id`, so `is_authenticated()` is false and the tenant
    /// gate treats API-key callers as anonymous (read-public, no writes).
    /// Tracked as a follow-up alongside the IdentityHub removal.
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
