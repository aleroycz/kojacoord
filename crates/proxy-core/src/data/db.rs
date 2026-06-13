//! Optional SQL backing store (MySQL or SQLite).
//!
//! When `[database] url` is set, the proxy persists player profiles,
//! purchases, role assignments, and ban records here. The SQLite
//! fallback is the default when no URL is configured — `data/proxy.db`
//! is created on the fly. The connection is optional throughout:
//! every consumer treats `db: Option<Arc<Db>>` and degrades to
//! in-memory-only behavior when it's `None`.

use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
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

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS players (
                uuid VARCHAR(36) NOT NULL PRIMARY KEY,
                username VARCHAR(16) NOT NULL,
                role VARCHAR(32) NOT NULL DEFAULT 'PLAYER',
                online TINYINT(1) NOT NULL DEFAULT 0,
                server VARCHAR(64) NULL,
                first_join TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_players_username (username)
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS player_bans (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                player_uuid VARCHAR(36) NOT NULL,
                reason TEXT NOT NULL,
                banned_by VARCHAR(64) NOT NULL,
                banned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NULL,
                active TINYINT(1) DEFAULT 1,
                INDEX idx_ban_uuid (player_uuid),
                INDEX idx_ban_active (active)
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS roles (
                name VARCHAR(32) NOT NULL PRIMARY KEY,
                display_name VARCHAR(64) NOT NULL,
                prefix VARCHAR(32) NOT NULL DEFAULT '',
                color VARCHAR(16) NOT NULL DEFAULT 'WHITE',
                weight INT NOT NULL DEFAULT 0,
                permissions JSON
            )",
        )
        .execute(&pool)
        .await?;

        // LuckPerms-shaped per-user permission nodes. `value` 1=grant,
        // 0=negate; `server` scopes the node to a backend (NULL = global).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS lp_user_nodes (
                uuid VARCHAR(36) NOT NULL,
                node VARCHAR(128) NOT NULL,
                value TINYINT(1) NOT NULL DEFAULT 1,
                server VARCHAR(64) NULL,
                PRIMARY KEY (uuid, node, server),
                INDEX idx_lp_user_nodes_uuid (uuid)
            )",
        )
        .execute(&pool)
        .await?;

        // Group (role) inheritance edges: `child` inherits `parent`'s nodes.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS lp_group_parents (
                child VARCHAR(32) NOT NULL,
                parent VARCHAR(32) NOT NULL,
                PRIMARY KEY (child, parent)
            )",
        )
        .execute(&pool)
        .await?;

        // See SQLite section for the rationale on this table.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS cached_profiles (
                uuid VARCHAR(36) NOT NULL PRIMARY KEY,
                username VARCHAR(32) NOT NULL,
                properties_json LONGTEXT NOT NULL,
                cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_cached_profiles_username (username)
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
        // `.connect("data/proxy.db")` treats the string as a connection
        // URL and, crucially, will NOT create the database file if it's
        // missing — first-run installs failed with "unable to open
        // database file". Build explicit connect options so the file
        // (and journal) are created on demand.
        let connect_options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect_with(connect_options)
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

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS players (
                uuid TEXT NOT NULL PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'PLAYER',
                online INTEGER NOT NULL DEFAULT 0,
                server TEXT,
                first_join TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(&pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_players_username ON players(username)")
            .execute(&pool)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS player_bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player_uuid TEXT NOT NULL,
                reason TEXT NOT NULL,
                banned_by TEXT NOT NULL,
                banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NULL,
                active INTEGER DEFAULT 1
            )",
        )
        .execute(&pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ban_uuid ON player_bans(player_uuid)")
            .execute(&pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ban_active ON player_bans(active)")
            .execute(&pool)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS roles (
                name TEXT NOT NULL PRIMARY KEY,
                display_name TEXT NOT NULL,
                prefix TEXT NOT NULL DEFAULT '',
                color TEXT NOT NULL DEFAULT 'WHITE',
                weight INTEGER NOT NULL DEFAULT 0,
                permissions TEXT
            )",
        )
        .execute(&pool)
        .await?;

        // LuckPerms-shaped per-user nodes (see MySQL section for semantics).
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS lp_user_nodes (
                uuid TEXT NOT NULL,
                node TEXT NOT NULL,
                value INTEGER NOT NULL DEFAULT 1,
                server TEXT,
                PRIMARY KEY (uuid, node, server)
            )",
        )
        .execute(&pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_lp_user_nodes_uuid ON lp_user_nodes(uuid)")
            .execute(&pool)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS lp_group_parents (
                child TEXT NOT NULL,
                parent TEXT NOT NULL,
                PRIMARY KEY (child, parent)
            )",
        )
        .execute(&pool)
        .await?;

        // Cached Mojang profile properties, keyed by online-mode UUID.
        //
        // Populated when a 1.7+ client completes Mojang `hasJoined`
        // verification AND the signature on each property is
        // successfully checked against the configured
        // `mojang_public_key`. Loaded when a 1.6.x client connects in
        // offline mode (1.6.x's session.minecraft.net endpoint has
        // been dead since 2014) so the proxy can synthesise their
        // skin from the cached signed property.
        //
        // `properties_json` is the serde-JSON serialisation of the
        // `Vec<ProfileProperty>` straight from `kojacoord-auth` —
        // includes `name`, base64 `value` and base64 `signature`. We
        // intentionally keep the original base64 envelope so a
        // re-verification at load time uses exactly the same bytes
        // Mojang signed.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS cached_profiles (
                uuid TEXT NOT NULL PRIMARY KEY,
                username TEXT NOT NULL,
                properties_json TEXT NOT NULL,
                cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_cached_profiles_username
                ON cached_profiles(username)",
        )
        .execute(&pool)
        .await?;

        Ok(Self {
            mysql_pool: None,
            sqlite_pool: Some(pool),
            db_type: DbType::Sqlite,
        })
    }

    /// Cache a Mojang-verified profile keyed by online-mode UUID.
    /// Called by `finalise_login` after `verify_properties` succeeds
    /// for a 1.7+ client in online mode.
    ///
    /// `properties` is serialised via `serde_json` — the on-disk
    /// payload preserves the **exact base64 `value` and `signature`
    /// bytes** Mojang signed, so a later `verify_property` call at
    /// load time hashes the same source bytes.
    pub async fn cache_player_profile(
        &self,
        uuid: uuid::Uuid,
        username: &str,
        properties: &[kojacoord_auth::ProfileProperty],
    ) -> Result<(), sqlx::Error> {
        let json = match serde_json::to_string(properties) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialise profile properties for cache");
                return Ok(());
            },
        };
        if let Some(pool) = &self.sqlite_pool {
            sqlx::query(
                "INSERT INTO cached_profiles (uuid, username, properties_json, cached_at)
                 VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                 ON CONFLICT(uuid) DO UPDATE SET
                    username = excluded.username,
                    properties_json = excluded.properties_json,
                    cached_at = CURRENT_TIMESTAMP",
            )
            .bind(uuid.to_string())
            .bind(username)
            .bind(&json)
            .execute(pool)
            .await?;
        } else if let Some(pool) = &self.mysql_pool {
            sqlx::query(
                "INSERT INTO cached_profiles (uuid, username, properties_json, cached_at)
                 VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                 ON DUPLICATE KEY UPDATE
                    username = VALUES(username),
                    properties_json = VALUES(properties_json),
                    cached_at = CURRENT_TIMESTAMP",
            )
            .bind(uuid.to_string())
            .bind(username)
            .bind(&json)
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    /// Look up a cached profile by **username** (1.6.x offline-mode
    /// path — the only key we have at that point is the legacy
    /// username, not the modern UUID). Returns the cached UUID +
    /// properties so limbo/relay can synthesise the player's skin.
    pub async fn load_cached_profile_by_username(
        &self,
        username: &str,
    ) -> Result<Option<(uuid::Uuid, Vec<kojacoord_auth::ProfileProperty>)>, sqlx::Error> {
        let row: Option<(String, String)> = if let Some(pool) = &self.sqlite_pool {
            sqlx::query_as(
                "SELECT uuid, properties_json FROM cached_profiles
                 WHERE username = ? COLLATE NOCASE
                 ORDER BY cached_at DESC LIMIT 1",
            )
            .bind(username)
            .fetch_optional(pool)
            .await?
        } else if let Some(pool) = &self.mysql_pool {
            sqlx::query_as(
                "SELECT uuid, properties_json FROM cached_profiles
                 WHERE LOWER(username) = LOWER(?)
                 ORDER BY cached_at DESC LIMIT 1",
            )
            .bind(username)
            .fetch_optional(pool)
            .await?
        } else {
            return Ok(None);
        };
        let Some((uuid_str, json)) = row else {
            return Ok(None);
        };
        let Ok(uuid) = uuid::Uuid::parse_str(&uuid_str) else {
            tracing::warn!(uuid = %uuid_str, "cached_profiles row has malformed UUID; dropping");
            return Ok(None);
        };
        let properties: Vec<kojacoord_auth::ProfileProperty> = match serde_json::from_str(&json) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "cached_profiles row has malformed properties_json");
                return Ok(None);
            },
        };
        Ok(Some((uuid, properties)))
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

    /// Load every per-user permission node: `(node, granted, server_context)`.
    pub async fn load_user_nodes(
        &self,
        uuid: Uuid,
    ) -> Result<Vec<(String, bool, Option<String>)>, sqlx::Error> {
        let uuid_str = uuid.hyphenated().to_string();
        macro_rules! map_rows {
            ($rows:expr) => {
                $rows
                    .into_iter()
                    .map(|r| {
                        (
                            r.get::<String, _>("node"),
                            r.get::<i64, _>("value") != 0,
                            r.get::<Option<String>, _>("server"),
                        )
                    })
                    .collect()
            };
        }
        let rows: Vec<(String, bool, Option<String>)> = if let Some(pool) = &self.mysql_pool {
            let rows = sqlx::query("SELECT node, value, server FROM lp_user_nodes WHERE uuid = ?")
                .bind(&uuid_str)
                .fetch_all(pool)
                .await?;
            map_rows!(rows)
        } else if let Some(pool) = &self.sqlite_pool {
            let rows = sqlx::query("SELECT node, value, server FROM lp_user_nodes WHERE uuid = ?")
                .bind(&uuid_str)
                .fetch_all(pool)
                .await?;
            map_rows!(rows)
        } else {
            Vec::new()
        };
        Ok(rows)
    }

    /// Grant or negate a node for a user (upsert). `server` scopes it to
    /// a backend; `None` is global.
    pub async fn set_user_node(
        &self,
        uuid: Uuid,
        node: &str,
        value: bool,
        server: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let uuid_str = uuid.hyphenated().to_string();
        let v = i32::from(value);
        if let Some(pool) = &self.mysql_pool {
            sqlx::query(
                "INSERT INTO lp_user_nodes (uuid, node, value, server) VALUES (?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE value = VALUES(value)",
            )
            .bind(&uuid_str)
            .bind(node)
            .bind(v)
            .bind(server)
            .execute(pool)
            .await
            .map(|_| ())
        } else if let Some(pool) = &self.sqlite_pool {
            sqlx::query(
                "INSERT INTO lp_user_nodes (uuid, node, value, server) VALUES (?, ?, ?, ?) \
                 ON CONFLICT(uuid, node, server) DO UPDATE SET value = excluded.value",
            )
            .bind(&uuid_str)
            .bind(node)
            .bind(v)
            .bind(server)
            .execute(pool)
            .await
            .map(|_| ())
        } else {
            Ok(())
        }
    }

    /// Remove a user node (any server context matching `server`).
    pub async fn delete_user_node(
        &self,
        uuid: Uuid,
        node: &str,
        server: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let uuid_str = uuid.hyphenated().to_string();
        let sql = "DELETE FROM lp_user_nodes WHERE uuid = ? AND node = ? AND server IS ?";
        if let Some(pool) = &self.mysql_pool {
            // MySQL has no `IS ?` null-safe bind for plain `?`; use <=>.
            sqlx::query("DELETE FROM lp_user_nodes WHERE uuid = ? AND node = ? AND server <=> ?")
                .bind(&uuid_str)
                .bind(node)
                .bind(server)
                .execute(pool)
                .await
                .map(|_| ())
        } else if let Some(pool) = &self.sqlite_pool {
            sqlx::query(sql)
                .bind(&uuid_str)
                .bind(node)
                .bind(server)
                .execute(pool)
                .await
                .map(|_| ())
        } else {
            Ok(())
        }
    }

    /// Load all group inheritance edges as `(child, parent)` pairs.
    pub async fn load_group_parents(&self) -> Result<Vec<(String, String)>, sqlx::Error> {
        macro_rules! map_rows {
            ($rows:expr) => {
                $rows
                    .into_iter()
                    .map(|r| (r.get::<String, _>("child"), r.get::<String, _>("parent")))
                    .collect()
            };
        }
        let rows: Vec<(String, String)> = if let Some(pool) = &self.mysql_pool {
            let rows = sqlx::query("SELECT child, parent FROM lp_group_parents")
                .fetch_all(pool)
                .await?;
            map_rows!(rows)
        } else if let Some(pool) = &self.sqlite_pool {
            let rows = sqlx::query("SELECT child, parent FROM lp_group_parents")
                .fetch_all(pool)
                .await?;
            map_rows!(rows)
        } else {
            Vec::new()
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

    pub async fn update_player_status(
        &self,
        uuid: Uuid,
        server: &str,
        online: bool,
    ) -> Result<(), sqlx::Error> {
        let uuid_str = uuid.hyphenated().to_string();
        match self.db_type {
            DbType::MySql => {
                if let Some(pool) = &self.mysql_pool {
                    sqlx::query(
                        "UPDATE players SET online = ?, last_seen = NOW(), server = ? WHERE uuid = ?"
                    )
                    .bind(online)
                    .bind(server)
                    .bind(&uuid_str)
                    .execute(pool)
                    .await?;
                }
            },
            DbType::Sqlite => {
                if let Some(pool) = &self.sqlite_pool {
                    sqlx::query(
                        "UPDATE players SET online = ?, last_seen = CURRENT_TIMESTAMP, server = ? WHERE uuid = ?"
                    )
                    .bind(online)
                    .bind(server)
                    .bind(&uuid_str)
                    .execute(pool)
                    .await?;
                }
            },
        }
        Ok(())
    }
}
