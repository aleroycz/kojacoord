use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub enum DbType {
    MySql,
    Sqlite,
}

#[derive(Clone)]
pub struct Db {
    mysql_pool: Option<MySqlPool>,
    sqlite_pool: Option<SqlitePool>,
    db_type: DbType,
}

#[derive(Debug, Clone)]
pub struct PendingPurchase {
    pub id: i64,
    pub username: String,
    pub product_slug: String,
    pub delivered: bool,
}

#[derive(Debug, Clone)]
pub struct RoleRow {
    pub name: String,
    pub display_name: String,
    pub prefix: String,
    pub color: String,
    pub weight: i32,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ActiveBan {
    pub reason: String,
    pub banned_by: String,
    pub expires_at: Option<chrono::NaiveDateTime>,
}

impl Db {
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, sqlx::Error> {
        let pool = MySqlPoolOptions::new()
            .max_connections(max_connections.max(1))
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(url)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pending_purchases (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                username TEXT NOT NULL,
                product_slug TEXT NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                delivered_at TIMESTAMP NULL
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            mysql_pool: Some(pool),
            sqlite_pool: None,
            db_type: DbType::MySql,
        })
    }

    pub async fn connect_sqlite(path: &str) -> Result<Self, sqlx::Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(path)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS offline_uuids (
                username TEXT PRIMARY KEY,
                uuid TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pending_purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                product_slug TEXT NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                delivered_at TIMESTAMP NULL
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            mysql_pool: None,
            sqlite_pool: Some(pool),
            db_type: DbType::Sqlite,
        })
    }

    pub fn mysql_pool(&self) -> Option<&MySqlPool> {
        self.mysql_pool.as_ref()
    }

    pub fn sqlite_pool(&self) -> Option<&SqlitePool> {
        self.sqlite_pool.as_ref()
    }

    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        match self.db_type {
            DbType::MySql => {
                if let Some(pool) = &self.mysql_pool {
                    sqlx::query("SELECT 1").execute(pool).await.map(|_| ())
                } else {
                    Err(sqlx::Error::Configuration("No MySQL pool".into()))
                }
            },
            DbType::Sqlite => {
                if let Some(pool) = &self.sqlite_pool {
                    sqlx::query("SELECT 1").execute(pool).await.map(|_| ())
                } else {
                    Err(sqlx::Error::Configuration("No SQLite pool".into()))
                }
            },
        }
    }

    pub async fn get_or_create_offline_uuid(&self, username: &str) -> Result<Uuid, sqlx::Error> {
        if let Some(uuid) = self.get_offline_uuid(username).await? {
            return Ok(uuid);
        }

        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(username.as_bytes());
        let hash = hasher.finalize();

        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        bytes[6] = (bytes[6] & 0x0F) | 0x50;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;

        let uuid = Uuid::from_bytes(bytes);

        if let Some(pool) = &self.sqlite_pool {
            sqlx::query("INSERT INTO offline_uuids (username, uuid) VALUES (?, ?)")
                .bind(username)
                .bind(uuid.hyphenated().to_string())
                .execute(pool)
                .await?;
        } else if let Some(pool) = &self.mysql_pool {
            sqlx::query("INSERT INTO offline_uuids (username, uuid) VALUES (?, ?)")
                .bind(username)
                .bind(uuid.hyphenated().to_string())
                .execute(pool)
                .await?;
        }

        Ok(uuid)
    }

    pub async fn get_offline_uuid(&self, username: &str) -> Result<Option<Uuid>, sqlx::Error> {
        let uuid_str = if let Some(pool) = &self.sqlite_pool {
            let row = sqlx::query("SELECT uuid FROM offline_uuids WHERE username = ?")
                .bind(username)
                .fetch_optional(pool)
                .await?;
            row.map(|r| r.get::<String, _>("uuid"))
        } else if let Some(pool) = &self.mysql_pool {
            let row = sqlx::query("SELECT uuid FROM offline_uuids WHERE username = ?")
                .bind(username)
                .fetch_optional(pool)
                .await?;
            row.map(|r| r.get::<String, _>("uuid"))
        } else {
            return Ok(None);
        };

        Ok(uuid_str.and_then(|s| Uuid::parse_str(&s).ok()))
    }

    pub async fn upsert_player_on_join(
        &self,
        uuid: Uuid,
        username: &str,
    ) -> Result<String, sqlx::Error> {
        match self.db_type {
            DbType::MySql => {
                if let Some(pool) = &self.mysql_pool {
                    sqlx::query(
                        "INSERT INTO players (uuid, username) VALUES (?, ?) ON DUPLICATE KEY UPDATE username = VALUES(username), last_seen = CURRENT_TIMESTAMP",
                    )
                    .bind(uuid.hyphenated().to_string())
                    .bind(username)
                    .execute(pool)
                    .await?;
                }
            },
            DbType::Sqlite => {
                if let Some(pool) = &self.sqlite_pool {
                    sqlx::query(
                        "INSERT INTO players (uuid, username) VALUES (?, ?) ON CONFLICT(uuid) DO UPDATE SET username = excluded.username, last_seen = CURRENT_TIMESTAMP",
                    )
                    .bind(uuid.hyphenated().to_string())
                    .bind(username)
                    .execute(pool)
                    .await?;
                }
            },
        }

        let rank = self
            .player_rank(uuid)
            .await?
            .unwrap_or_else(|| "PLAYER".to_owned());
        Ok(rank)
    }

    pub async fn player_rank(&self, uuid: Uuid) -> Result<Option<String>, sqlx::Error> {
        let uuid_str = uuid.hyphenated().to_string();
        match self.db_type {
            DbType::MySql => {
                let Some(pool) = &self.mysql_pool else {
                    return Ok(None);
                };
                let row = sqlx::query("SELECT role FROM players WHERE uuid = ? LIMIT 1")
                    .bind(&uuid_str)
                    .fetch_optional(pool)
                    .await?;
                Ok(row.map(|r| r.get::<String, _>("role")))
            },
            DbType::Sqlite => {
                let Some(pool) = &self.sqlite_pool else {
                    return Ok(None);
                };
                let row = sqlx::query("SELECT role FROM players WHERE uuid = ? LIMIT 1")
                    .bind(&uuid_str)
                    .fetch_optional(pool)
                    .await?;
                Ok(row.map(|r| r.get::<String, _>("role")))
            },
        }
    }

    pub async fn load_roles(&self) -> Result<Vec<RoleRow>, sqlx::Error> {
        macro_rules! map_rows {
            ($rows:expr) => {
                $rows
                    .into_iter()
                    .map(|r| {
                        use sqlx::Row;
                        let permissions = r
                            .get::<Option<String>, _>("permissions")
                            .and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok())
                            .unwrap_or_default();
                        RoleRow {
                            name: r.get::<String, _>("name"),
                            display_name: r.get::<String, _>("display_name"),
                            prefix: r.get::<String, _>("prefix"),
                            color: r.get::<String, _>("color"),
                            weight: r.get::<i32, _>("weight"),
                            permissions,
                        }
                    })
                    .collect()
            };
        }

        let rows: Vec<RoleRow> = match self.db_type {
            DbType::MySql => {
                let Some(pool) = &self.mysql_pool else {
                    return Ok(vec![]);
                };
                let rows = sqlx::query(
                    "SELECT name, display_name, prefix, color, weight, CAST(permissions AS CHAR) as permissions FROM roles",
                )
                .fetch_all(pool)
                .await?;
                map_rows!(rows)
            },
            DbType::Sqlite => {
                let Some(pool) = &self.sqlite_pool else {
                    return Ok(vec![]);
                };
                let rows = sqlx::query(
                    "SELECT name, display_name, prefix, color, weight, permissions FROM roles",
                )
                .fetch_all(pool)
                .await?;
                map_rows!(rows)
            },
        };

        Ok(rows)
    }

    pub async fn insert_ban(
        &self,
        uuid: Uuid,
        reason: &str,
        banned_by: &str,
        expires_at: Option<chrono::NaiveDateTime>,
    ) -> Result<(), sqlx::Error> {
        match self.db_type {
            DbType::MySql => {
                if let Some(pool) = &self.mysql_pool {
                    sqlx::query("INSERT INTO player_bans (player_uuid, reason, banned_by, expires_at, active) VALUES (?, ?, ?, ?, 1)")
                        .bind(uuid.hyphenated().to_string())
                        .bind(reason)
                        .bind(banned_by)
                        .bind(expires_at)
                        .execute(pool)
                        .await
                        .map(|_| ())
                } else {
                    Ok(())
                }
            },
            DbType::Sqlite => {
                if let Some(pool) = &self.sqlite_pool {
                    sqlx::query("INSERT INTO player_bans (player_uuid, reason, banned_by, expires_at, active) VALUES (?, ?, ?, ?, 1)")
                        .bind(uuid.hyphenated().to_string())
                        .bind(reason)
                        .bind(banned_by)
                        .bind(expires_at)
                        .execute(pool)
                        .await
                        .map(|_| ())
                } else {
                    Ok(())
                }
            },
        }
    }

    pub async fn uuid_for_username(&self, username: &str) -> Result<Option<Uuid>, sqlx::Error> {
        let uuid_str = if let Some(pool) = &self.mysql_pool {
            let row = sqlx::query(
                "SELECT uuid FROM players WHERE username = ? ORDER BY last_seen DESC LIMIT 1",
            )
            .bind(username)
            .fetch_optional(pool)
            .await?;
            row.map(|r| r.get::<String, _>("uuid"))
        } else if let Some(pool) = &self.sqlite_pool {
            let row = sqlx::query(
                "SELECT uuid FROM players WHERE username = ? ORDER BY last_seen DESC LIMIT 1",
            )
            .bind(username)
            .fetch_optional(pool)
            .await?;
            row.map(|r| r.get::<String, _>("uuid"))
        } else {
            return Ok(None);
        };
        Ok(uuid_str.and_then(|s| Uuid::parse_str(&s).ok()))
    }

    pub async fn active_ban(&self, uuid: Uuid) -> Result<Option<ActiveBan>, sqlx::Error> {
        match self.db_type {
            DbType::MySql => {
                if let Some(pool) = &self.mysql_pool {
                    let row = sqlx::query(
                        "SELECT reason, banned_by, expires_at FROM player_bans WHERE player_uuid = ? AND active = 1 AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY banned_at DESC LIMIT 1",
                    )
                    .bind(uuid.hyphenated().to_string())
                    .fetch_optional(pool)
                    .await?;
                    if let Some(r) = row {
                        let expires_at_str = r.get::<Option<String>, _>("expires_at");
                        let expires_at = expires_at_str.and_then(|s| {
                            chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S%.f").ok()
                        });
                        return Ok(Some(ActiveBan {
                            reason: r.get::<String, _>("reason"),
                            banned_by: r.get::<String, _>("banned_by"),
                            expires_at,
                        }));
                    }
                }
                Ok(None)
            },
            DbType::Sqlite => {
                if let Some(pool) = &self.sqlite_pool {
                    let row = sqlx::query(
                        "SELECT reason, banned_by, expires_at FROM player_bans WHERE player_uuid = ? AND active = 1 AND (expires_at IS NULL OR datetime(expires_at) > datetime('now')) ORDER BY banned_at DESC LIMIT 1",
                    )
                    .bind(uuid.hyphenated().to_string())
                    .fetch_optional(pool)
                    .await?;
                    if let Some(r) = row {
                        let expires_at_str = r.get::<Option<String>, _>("expires_at");
                        let expires_at = expires_at_str.and_then(|s| {
                            chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S").ok()
                        });
                        return Ok(Some(ActiveBan {
                            reason: r.get::<String, _>("reason"),
                            banned_by: r.get::<String, _>("banned_by"),
                            expires_at,
                        }));
                    }
                }
                Ok(None)
            },
        }
    }

    pub async fn add_pending_purchase(
        &self,
        username: &str,
        product_slug: &str,
    ) -> Result<i64, sqlx::Error> {
        let username_normalized = username.to_lowercase();
        let id = match self.db_type {
            DbType::MySql => {
                if let Some(pool) = &self.mysql_pool {
                    let result = sqlx::query("INSERT INTO pending_purchases (username, product_slug, delivered) VALUES (?, ?, 0)")
                        .bind(&username_normalized)
                        .bind(product_slug)
                        .execute(pool)
                        .await?;
                    result.last_insert_id() as i64
                } else {
                    return Err(sqlx::Error::Configuration("No MySQL pool".into()));
                }
            },
            DbType::Sqlite => {
                if let Some(pool) = &self.sqlite_pool {
                    let result = sqlx::query("INSERT INTO pending_purchases (username, product_slug, delivered) VALUES (?, ?, 0)")
                        .bind(&username_normalized)
                        .bind(product_slug)
                        .execute(pool)
                        .await?;
                    result.last_insert_rowid()
                } else {
                    return Err(sqlx::Error::Configuration("No SQLite pool".into()));
                }
            },
        };
        Ok(id)
    }

    pub async fn get_pending_purchases(
        &self,
        username: &str,
    ) -> Result<Vec<PendingPurchase>, sqlx::Error> {
        let username_normalized = username.to_lowercase();
        let mut list = Vec::new();
        match self.db_type {
            DbType::MySql => {
                if let Some(pool) = &self.mysql_pool {
                    let rows = sqlx::query("SELECT id, username, product_slug, delivered FROM pending_purchases WHERE username = ? AND delivered = 0")
                        .bind(&username_normalized)
                        .fetch_all(pool)
                        .await?;
                    for r in rows {
                        list.push(PendingPurchase {
                            id: r.get::<i64, _>("id"),
                            username: r.get::<String, _>("username"),
                            product_slug: r.get::<String, _>("product_slug"),
                            delivered: r.get::<i8, _>("delivered") != 0,
                        });
                    }
                }
            },
            DbType::Sqlite => {
                if let Some(pool) = &self.sqlite_pool {
                    let rows = sqlx::query("SELECT id, username, product_slug, delivered FROM pending_purchases WHERE username = ? AND delivered = 0")
                        .bind(&username_normalized)
                        .fetch_all(pool)
                        .await?;
                    for r in rows {
                        let delivered_val: i32 = r.get("delivered");
                        list.push(PendingPurchase {
                            id: r.get::<i64, _>("id"),
                            username: r.get::<String, _>("username"),
                            product_slug: r.get::<String, _>("product_slug"),
                            delivered: delivered_val != 0,
                        });
                    }
                }
            },
        }
        Ok(list)
    }

    pub async fn mark_purchase_delivered(&self, id: i64) -> Result<(), sqlx::Error> {
        match self.db_type {
            DbType::MySql => {
                if let Some(pool) = &self.mysql_pool {
                    sqlx::query("UPDATE pending_purchases SET delivered = 1, delivered_at = CURRENT_TIMESTAMP WHERE id = ?")
                        .bind(id)
                        .execute(pool)
                        .await?;
                }
            },
            DbType::Sqlite => {
                if let Some(pool) = &self.sqlite_pool {
                    sqlx::query("UPDATE pending_purchases SET delivered = 1, delivered_at = CURRENT_TIMESTAMP WHERE id = ?")
                        .bind(id)
                        .execute(pool)
                        .await?;
                }
            },
        }
        Ok(())
    }
}
