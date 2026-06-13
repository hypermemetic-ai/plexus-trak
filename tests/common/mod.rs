//! Shared OIDC test fixtures for the UT-W3 cutover suites.
//!
//! Mirrors the fixture pattern of plexus-auth-core's
//! `tests/oidc_validator.rs` (the UT-1 branch): an in-process "IdP"
//! implementing [`JwksFetcher`] serves a canned discovery document and
//! JWKS — the injected-fetcher seam the validator is designed around, so
//! no network is involved. The RSA fixture keypair is the same offline
//! (openssl) generated key UT-1's suite uses; it cannot mint
//! production-trusted tokens because production validators discover keys
//! from their configured issuer, not from these fixtures.

#![allow(dead_code)] // each integration test binary uses a subset

use std::sync::Arc;

use async_trait::async_trait;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;

use plexus_auth_core::oidc::{
    Audience, FetchError, FetchedDocument, JwksFetcher, OidcConfig, OidcValidator,
};
use plexus_auth_core::IssuerUrl;
use plexus_trak::auth::TrakAuth;
use plexus_trak::store::identity::IdentityStore;

pub const ISSUER: &str = "https://idp.test";
pub const AUDIENCE: &str = "plexus:trak";
pub const KID_1: &str = "utw3-key-1";

pub const KEY_1_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDRK77i+LgwjT95
0Uq+AQQe9Ls/PamwwyIrbCK+23//1oufPKD6x8TSWBVRXX5adtks140U6WU89Chs
sZTqyGFP23RjXrXTE9YXUAxL+5SKfoLVmZ0frz1kaCA09oW7+J6GczbYCIp9HNr3
dF4klIh2zqzoEYS4bNgZpI/xWHIWX2BAmXOg3Nb1/F3Z6rFWgxft3QkG9+/SftJ5
wmUVqvwa9+IG/TkNhE8VTfmfm/KRvMIbinckoUDoiawAf2sk3SOS1r6XHwPV2AjO
mukGfPQ+6BaggFOqzls7mH2n9KEsASNHDAKz242sSR+mYPF4afrXSzeDsUenMK0l
4kmzw1cVAgMBAAECggEABLrihCtvrtli2BRdhlJrj2+lVFbGoZKoESdO2dYI3PYz
DhTG5yThVIhdYwukMdOCMbtmG1Tzzx8OUvbpES4a1T13MlAP+If4TWqn/Ifh4gfe
WYoxvWevEbgxEkGI4KlMnGm6kcQPraibYwEkp9scAuPFkTHkOG9tq5bHEoQXgF35
Q1OxUI+S2YFH+5gY9pUWqLTkhc1iCb2b0YWZeYVs7eQvblajiCZagNXgWDBf05sE
AylUFMUzJV12Z0udyQal8H7ObuISxa6o57124Ib4x0V/LVXtAbdZQMru/Ymx6xxk
haBt8htLcFZdRC/RDCPNsd0fjsrqpARIF8jo+rgzeQKBgQD9BDU9zph03HYqHQZU
caizwE+G7fXswuhqlxmy94L/zL/Y2XpLMzDaPjv3S8wOrYQNx8uJpxycgJ2K7slM
M9qKL3UlkjsuS7DtGLFrvBQyC2KVMrMPBaSNOwnhSVWCyCRsSiiuACIFAWS9icS3
Eb1MqYAg2gdtB3QvhDb75IBYwwKBgQDToy3b8/h6ybIqmqz9bJ4QQwzHEs43uZ/P
VXVkiXHXHJ9zfq/dIjSYkIbsNJhD8CrzhOrvM11Fpah0i1EN5uqYJ3wKC13ZCWMe
wDZstYipoVYY80/M02Vnt0iEGsoNUojTqMWxixbkSHbvUUgQQpkEQrnqHEfV+LXo
X4JnyNbTRwKBgFZsw4rzMNxqGerUsz7Q/CE6RW//hIt1IFKYfmzFYvfhhn6Z+s4J
FFzX+T/FolQ5LOxQHNROQtWqkSXN3vCqnbGp+Ef3JUPxEuRKFQCJ5BQcE3aHNOai
tMyRKBTOKelcWCStSCv3W6d+DF052/n0k0bGdz/BedviOeupK+bq7HRlAoGAeaxA
+0miO4WmBtRyTCicHyFNQU5QfL0dYafyG+DhMBjmmxHkra+yqVu+FiKOv9BeAS8T
mn3fS+FXndlSujld+igJKgUq6VJ6R/2dzJX5gfydcS7BXDLVA/HdoQV90Hb47ycC
sXYTrR70MdZ7Jc4EBu0N0ch8jEm222e9o0lWKJUCgYBXxOLoBstghiOh7+q2C3l4
g8jv2q8ISuQn2Ov+e6w9TLX9FDAGMBt+7XTeQvB4UHnzugPL4ThHPzaHSZZ2MSe0
cc/8jPBcPehKNhhgDUFkmptSZn7hFSAkzdjoC4yYxu9OsftU9M3Fvg2awbJ/j78w
ibtF9Ayucd2RXBc2n+6vZg==
-----END PRIVATE KEY-----";

/// Public JWK for `KEY_1_PEM` (n/e computed offline from the modulus).
pub const JWK_1: &str = r#"{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "utw3-key-1", "n": "0Su-4vi4MI0_edFKvgEEHvS7Pz2psMMiK2wivtt__9aLnzyg-sfE0lgVUV1-WnbZLNeNFOllPPQobLGU6shhT9t0Y1610xPWF1AMS_uUin6C1ZmdH689ZGggNPaFu_iehnM22AiKfRza93ReJJSIds6s6BGEuGzYGaSP8VhyFl9gQJlzoNzW9fxd2eqxVoMX7d0JBvfv0n7SecJlFar8GvfiBv05DYRPFU35n5vykbzCG4p3JKFA6ImsAH9rJN0jkta-lx8D1dgIzprpBnz0PugWoIBTqs5bO5h9p_ShLAEjRwwCs9uNrEkfpmDxeGn610s3g7FHpzCtJeJJs8NXFQ", "e": "AQAB"}"#;

/// In-process "IdP": serves a canned discovery document and JWKS.
pub struct FixtureIdp;

#[async_trait]
impl JwksFetcher for FixtureIdp {
    async fn fetch(&self, url: &url::Url) -> Result<FetchedDocument, FetchError> {
        match url.path() {
            "/.well-known/openid-configuration" => Ok(FetchedDocument {
                body: json!({
                    "issuer": ISSUER,
                    "jwks_uri": format!("{ISSUER}/jwks.json"),
                    "token_endpoint": format!("{ISSUER}/oauth/token"),
                    "id_token_signing_alg_values_supported": ["RS256"],
                })
                .to_string(),
                cache_control: None,
            }),
            "/jwks.json" => Ok(FetchedDocument {
                body: format!(r#"{{"keys": [{JWK_1}]}}"#),
                cache_control: None,
            }),
            other => Err(FetchError(format!("fixture IdP has no route {other}"))),
        }
    }
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn fixture_config() -> OidcConfig {
    OidcConfig::new(
        IssuerUrl::try_new(ISSUER.parse().unwrap()).unwrap(),
        Audience::try_new(AUDIENCE).unwrap(),
    )
}

/// An [`OidcValidator`] wired to the fixture IdP (no network).
pub fn fixture_validator() -> OidcValidator {
    OidcValidator::with_fetcher(fixture_config(), Arc::new(FixtureIdp))
}

/// A [`TrakAuth`] over the fixture validator + the given identity store
/// (API-key fallback intact).
pub fn fixture_trak_auth(identity_store: IdentityStore) -> TrakAuth {
    TrakAuth::with_validator(identity_store, fixture_validator())
}

/// Standard valid claim set; tests override fields as needed.
pub fn claims() -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert("sub".into(), json!("user_alice"));
    m.insert("iss".into(), json!(ISSUER));
    m.insert("aud".into(), json!(AUDIENCE));
    m.insert("exp".into(), json!(now() + 3600));
    m.insert("iat".into(), json!(now() - 10));
    m
}

/// Mint an RS256 token with the fixture key.
pub fn mint(kid: &str, pem: &str, claims: serde_json::Map<String, serde_json::Value>) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(
        &header,
        &serde_json::Value::Object(claims),
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

/// Mint a valid plexus-idp-shaped token for `user` in `org` (with the
/// plexus extension claims).
pub fn mint_for(user: &str, org: Option<&str>) -> String {
    let mut c = claims();
    c.insert("sub".into(), json!(user));
    c.insert("username".into(), json!(user));
    c.insert("roles".into(), json!(["user"]));
    if let Some(org) = org {
        c.insert("org_id".into(), json!(org));
    }
    mint(KID_1, KEY_1_PEM, c)
}
