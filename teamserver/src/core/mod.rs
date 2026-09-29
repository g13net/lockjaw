use anyhow::Result;
use crate::storage::{Storage, Task};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::info;

pub enum CoreEvent {
    AgentCheckin {
        agent_id: String,
        hostname: String,
        username: String,
        ip_address: String,
        external_ip: String,
        sleep: i32,
        responder: oneshot::Sender<Result<Vec<Task>>>,
    },
    TaskResult {
        task_id: String,
        output: Vec<u8>,
    },
}

pub struct Core {
    storage: Arc<Storage>,
    event_rx: mpsc::Receiver<CoreEvent>,
}

impl Core {
    pub fn new(storage: Arc<Storage>, event_rx: mpsc::Receiver<CoreEvent>) -> Self {
        Self { storage, event_rx }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Core manager is running...");
        
        while let Some(event) = self.event_rx.recv().await {
            match event {
                CoreEvent::AgentCheckin { agent_id, hostname, username, ip_address, external_ip, sleep, responder } => {
                    let result = self.handle_checkin(agent_id, hostname, username, ip_address, external_ip, sleep).await;
                    let _ = responder.send(result);
                }
                CoreEvent::TaskResult { task_id, output } => {
                    let _ = self.handle_task_result(task_id, output).await;
                }
            }
        }
        
        Ok(())
    }

    async fn handle_checkin(&self, agent_id: String, hostname: String, username: String, ip_address: String, external_ip: String, sleep: i32) -> Result<Vec<Task>> {
        info!("Agent checkin from {}: {}@{} (Internal: {}, External: {})", agent_id, username, hostname, ip_address, external_ip);
        
        // UPSERT the agent into the database
        sqlx::query(
            "INSERT INTO agents (id, hostname, username, ip_address, external_ip, sleep, last_seen) 
             VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(id) DO UPDATE SET 
             hostname=excluded.hostname, 
             username=excluded.username, 
             ip_address=excluded.ip_address, 
             external_ip=excluded.external_ip, 
             sleep=excluded.sleep,
             last_seen=CURRENT_TIMESTAMP"
        )
        .bind(&agent_id)
        .bind(hostname)
        .bind(username)
        .bind(ip_address)
        .bind(external_ip)
        .bind(sleep)
        .execute(self.storage.pool())
        .await?;

        // Retrieve pending tasks
        let tasks = self.storage.get_pending_tasks(&agent_id).await?;
        
        Ok(tasks)
    }

    async fn handle_task_result(&self, task_id: String, output: Vec<u8>) -> Result<()> {
        info!("Task result received for {}", task_id);
        
        sqlx::query(
            "INSERT INTO results (task_id, output) VALUES (?, ?)"
        )
        .bind(&task_id)
        .bind(output)
        .execute(self.storage.pool())
        .await?;

        sqlx::query(
            "UPDATE tasks SET status='COMPLETED', completed_at=CURRENT_TIMESTAMP WHERE id=?"
        )
        .bind(task_id)
        .execute(self.storage.pool())
        .await?;
        
        Ok(())
    }
}
