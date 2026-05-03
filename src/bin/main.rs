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
use plexus_trak::hubs::identity::IdentityHub;
use plexus_trak::hubs::refs::RefsHub;
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

    let trak_auth = Arc::new(TrakAuth::new(identity_store.clone(), jwt_secret.clone()));

    let hub = Arc::new(
        DynamicHub::new("trak")
            .register(FacetHub::new(store))
            .register(IdentityHub::new(identity_store, jwt_secret))
            .register(DiscussHub::new())
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
