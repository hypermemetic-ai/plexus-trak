use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use plexus_core::plexus::DynamicHub;
use plexus_transport::TransportServer;

use plexus_trak::hubs::facet::FacetHub;
use plexus_trak::hubs::access::AccessHub;
use plexus_trak::hubs::audit::AuditHub;
use plexus_trak::hubs::collab::CollabHub;
use plexus_trak::hubs::discuss::DiscussHub;
use plexus_trak::hubs::docs::DocsHub;
use plexus_trak::hubs::identity::IdentityHub;
use plexus_trak::hubs::refs::RefsHub;
use plexus_trak::store::discuss::DiscussStore;
use plexus_trak::store::identity::IdentityStore;
use plexus_trak::store::sqlite::SqliteStore;
use plexus_trak::auth::TrakAuth;

/// CLI arguments for plexus-trak
#[derive(Parser, Debug)]
#[command(name = "plexus-trak")]
#[command(about = "Recursive facet tracker — Plexus RPC server")]
struct Args {
    /// Port for WebSocket server
    #[arg(short, long, default_value = "44107")]
    port: u16,

    /// Path to SQLite database
    #[arg(long)]
    db: Option<String>,

    /// Trusted OIDC issuer URL (plexus-idp or any compliant IdP, e.g. a
    /// real Auth0 tenant). Tokens are validated locally against the
    /// issuer's published JWKS — no shared secrets (UT-S01 D1).
    #[arg(long, env = "TRAK_OIDC_ISSUER", default_value = plexus_trak::auth::DEFAULT_OIDC_ISSUER)]
    oidc_issuer: String,

    /// Expected token audience (per-backend API identifier; a token
    /// minted for another backend must not replay here).
    #[arg(long, env = "TRAK_OIDC_AUDIENCE", default_value = plexus_trak::auth::DEFAULT_OIDC_AUDIENCE)]
    oidc_audience: String,
}

fn default_db_path() -> String {
    dirs::config_dir()
        .map(|c| c.join("trak").join("trak.db"))
        .unwrap_or_else(|| PathBuf::from("/tmp/trak/trak.db"))
        .to_string_lossy()
        .into_owned()
}

fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .map(|c| c.join("trak"))
        .unwrap_or_else(|| PathBuf::from("/tmp/trak"))
}

/// Load or generate the JWT secret key.
///
/// DEPRECATED (UT-W3 / 74103adf): this secret feeds ONLY the IdentityHub's
/// HS256 *mint* paths, which are themselves deprecated pending the
/// IdentityHub → plexus-idp removal. `TrakAuth` no longer reads it —
/// tokens minted with it are NOT accepted by this daemon. The post-deploy
/// runbook step deletes the file outright.
fn load_or_create_jwt_secret(config_dir: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    let secret_path = config_dir.join("jwt_secret");
    if secret_path.exists() {
        let bytes = std::fs::read(&secret_path)?;
        if bytes.len() >= 32 {
            return Ok(bytes);
        }
        tracing::warn!("jwt_secret too short, regenerating");
    }

    // Generate 64 random bytes
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let secret: Vec<u8> = (0..64).map(|_| rng.gen()).collect();

    std::fs::create_dir_all(config_dir)?;
    std::fs::write(&secret_path, &secret)?;
    tracing::info!("Generated new JWT secret at {}", secret_path.display());

    Ok(secret)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,plexus_trak=info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let db_path = args.db.unwrap_or_else(default_db_path);
    tracing::info!("Opening database at {db_path}");

    let config_dir = default_config_dir();
    let jwt_secret = load_or_create_jwt_secret(&config_dir)?;

    let store = Arc::new(SqliteStore::new(&db_path).await?);
    let identity_store = IdentityStore::new(store.pool().clone());
    let discuss_store = Arc::new(DiscussStore::new(store.pool().clone()));
    discuss_store.migrate().await?;

    // UT-W3: session validation is OIDC (RS256 against the issuer's JWKS,
    // discovery-resolved, AUTH-8 caching) + the unchanged API-key fallback.
    // The HS256 shared-secret validation path is gone (closes 74103adf).
    let oidc_config =
        plexus_trak::auth::oidc_config(&args.oidc_issuer, &args.oidc_audience)?;
    tracing::info!(
        issuer = %args.oidc_issuer,
        audience = %args.oidc_audience,
        "OIDC session validation enabled (RS256 via issuer JWKS; HS256 path removed)"
    );
    let trak_auth = Arc::new(TrakAuth::new(identity_store.clone(), oidc_config));

    let hub = Arc::new(
        DynamicHub::new("trak")
            .register(FacetHub::new(store.clone()))
            .register(IdentityHub::new(identity_store, jwt_secret))
            .register(DiscussHub::new(discuss_store))
            .register(DocsHub::new(store))
            .register(AuditHub::new())
            .register(AccessHub::new())
            .register(CollabHub::new())
            .register(RefsHub::new()),
    );

    tracing::info!(port = args.port, "plexus-trak starting");

    let rpc_converter = |arc: Arc<DynamicHub>| {
        DynamicHub::arc_into_rpc_module(arc)
            .map_err(|e| anyhow::anyhow!("Failed to create RPC module: {e}"))
    };

    let server = TransportServer::builder(hub, rpc_converter)
        .with_session_validator(trak_auth)
        .with_websocket(args.port)
        .build()
        .await?;

    tokio::select! {
        res = server.serve() => res,
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}
