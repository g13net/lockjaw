use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, error};
use std::sync::Arc;
use std::net::SocketAddr;
use std::path::PathBuf;
use clap::Parser;

mod core;
mod listeners;
mod storage;
mod operator;
mod utils;

use crate::core::{Core, CoreEvent};
use crate::storage::Storage;
use crate::listeners::ListenerManager;
use crate::operator::OperatorApi;
use crate::utils::get_or_generate_self_signed;
use tracing_subscriber::fmt::time::ChronoLocal;
use axum_server::Handle;


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port for the Operator REST API
    #[arg(long, default_value_t = 50051)]
    op_port: u16,

    /// Host for the Operator REST API
    #[arg(long, default_value = "127.0.0.1")]
    op_host: String,

    /// Do not start the default HTTP agent listener
    #[arg(long, default_value_t = false)]
    no_listeners: bool,

    /// Port for the default HTTP agent listener
    #[arg(long, default_value_t = 8080)]
    http_port: u16,

    /// Host for the default HTTP agent listener
    #[arg(long, default_value = "127.0.0.1")]
    http_host: String,

    /// Path to the SQLite database
    #[arg(long, default_value = "lockjaw.db")]
    db_path: String,

    /// Static API key for operator authentication
    #[arg(long, default_value = "lockjaw_secret_key")]
    api_key: String,

    /// Path to the SSL certificate for the Operator API
    #[arg(long, default_value = "op_cert.pem")]
    op_cert: String,

    /// Path to the SSL key for the Operator API
    #[arg(long, default_value = "op_key.pem")]
    op_key: String,

    /// Path to the SSL certificate for the Agent Listener
    #[arg(long, default_value = "agent_cert.pem")]
    agent_cert: String,

    /// Path to the SSL key for the Agent Listener
    #[arg(long, default_value = "agent_key.pem")]
    agent_key: String,
}

use tokio_util::sync::CancellationToken;

async fn wait_for_shutdown() {
    // Wait for the first signal and exit immediately
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            info!("Shutdown signal received. Exiting immediately.");
            std::process::exit(0);
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install default crypto provider for rustls
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing with local timezone support and default info level
    tracing_subscriber::fmt()
        .with_timer(ChronoLocal::rfc_3339())
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    info!("Starting Lockjaw Teamserver v{}...", env!("CARGO_PKG_VERSION"));

    // Ensure SSL certificates exist
    info!("Ensuring SSL certificates exist...");
    get_or_generate_self_signed(&args.op_cert, &args.op_key, "Lockjaw Operator API")?;
    get_or_generate_self_signed(&args.agent_cert, &args.agent_key, "Lockjaw Agent Listener")?;

    // Create a broad cancellation token (kept for module compatibility, though main exits early)
    let token = CancellationToken::new();

    // Initialize Storage (SQLite)
    let storage = Arc::new(Storage::new(&args.db_path).await?);

    // Create a shared handle for axum servers
    let shutdown_handle = Handle::new();

    // Create communication channels for listeners
    let (tx, rx) = mpsc::channel::<CoreEvent>(100);

    // Initialize Listener Manager
    let listener_manager = Arc::new(ListenerManager::new(tx.clone(), token.clone()));

    // Initialize Core Manager
    let core = Core::new(Arc::clone(&storage), rx);

    // Spawn Signal Handler (Handles immediate exit)
    tokio::spawn(async move {
        wait_for_shutdown().await;
    });

    // Spawn Core Manager
    let core_token = token.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = core_token.cancelled() => {}
            res = core.run() => {
                if let Err(e) = res {
                    error!("Core manager error: {}", e);
                }
            }
        }
    });

    // Start HTTP Listener if not disabled
    if !args.no_listeners {
        let addr_str = format!("{}:{}", args.http_host, args.http_port);
        let addr: SocketAddr = addr_str.parse()?;
        
        let lm = Arc::clone(&listener_manager);
        let cert = PathBuf::from(&args.agent_cert);
        let key = PathBuf::from(&args.agent_key);
        
        // Use default key for now
        let session_key = "deadbeefdeadbeefdeadbeefdeadbeef".to_string();
        
        tokio::spawn(async move {
            if let Err(e) = lm.start_https(addr, cert, key, session_key).await {
                error!("Failed to start default HTTPS listener: {}", e);
            }
        });
    }

    // Start Operator API
    let op_addr_str = format!("{}:{}", args.op_host, args.op_port);
    let op_addr: SocketAddr = op_addr_str.parse()?;
    
    let operator_api = OperatorApi::new(
        Arc::clone(&storage), 
        args.api_key,
        PathBuf::from(&args.op_cert),
        PathBuf::from(&args.op_key),
        PathBuf::from(&args.agent_cert),
        PathBuf::from(&args.agent_key),
        shutdown_handle.clone(),
        Arc::clone(&listener_manager)
    );

    let op_token = token.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = op_token.cancelled() => {}
            res = operator_api.run(op_addr) => {
                if let Err(e) = res {
                    error!("Operator HTTPS API error: {}", e);
                }
            }
        }
    });

    info!("Teamserver is running.");

    // The main task now simply parks and waits to be killed by the signal handler's process::exit
    std::future::pending::<()>().await;

    Ok(())
}
