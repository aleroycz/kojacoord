//! Leader election and heartbeat for clustered proxies.
//!
//! Each proxy refreshes its own row in [`ServiceDiscovery`] and runs
//! `elect_leader` periodically; the lowest-UUID alive node becomes
//! leader. Coarse but deterministic — no external coordinator (etcd,
//! ZooKeeper) needed.

use crate::discovery::ServiceDiscovery;
use crate::node::{ClusterNode, NodeRole};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct ClusterCoordinator {
    discovery: Arc<ServiceDiscovery>,
    leader_id: Arc<RwLock<Option<Uuid>>>,
    local_node_id: Uuid,
    redis_client: Option<redis::Client>,
}

impl ClusterCoordinator {
    pub fn new(discovery: Arc<ServiceDiscovery>, local_node_id: Uuid) -> Self {
        let raw_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
        let redis_url = if raw_url.starts_with("redis://") || raw_url.starts_with("rediss://") {
            raw_url
        } else {
            tracing::warn!(
                "REDIS_URL does not start with redis:// or rediss://, falling back to default"
            );
            "redis://127.0.0.1/".to_string()
        };
        let redis_client = match redis::Client::open(redis_url.clone()) {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::warn!("Failed to create Redis client for '{}': {}", redis_url, e);
                None
            },
        };

        Self {
            discovery,
            leader_id: Arc::new(RwLock::new(None)),
            local_node_id,
            redis_client,
        }
    }

    pub async fn initialize(
        &self,
        local_address: SocketAddr,
        max_players: usize,
    ) -> anyhow::Result<()> {
        let local_node = ClusterNode::new(local_address, NodeRole::Standalone, max_players);
        self.discovery.register_node(local_node);

        self.elect_leader().await?;

        Ok(())
    }

    pub async fn elect_leader(&self) -> anyhow::Result<()> {
        let nodes = self.discovery.get_healthy_nodes();

        if nodes.is_empty() {
            *self.leader_id.write().await = None;
            return Ok(());
        }

        let mut leader_id = None;

        if let Some(client) = &self.redis_client {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let current_leader: Option<String> = redis::cmd("GET")
                    .arg("cluster_leader_lock")
                    .query_async(&mut conn)
                    .await
                    .ok();

                let is_us = current_leader.as_deref() == Some(&self.local_node_id.to_string());

                if is_us {
                    // If we're already the leader, renew our Redis lease so we keep the role.
                    let lua_script = r#"
                        local key = KEYS[1]
                        local expected_value = ARGV[1]
                        local ttl = ARGV[2]
                        local current = redis.call('GET', key)
                        if current == expected_value then
                            redis.call('SETEX', key, ttl, expected_value)
                            return 1
                        else
                            return 0
                        end
                    "#;

                    let result: Result<i32, _> = redis::cmd("EVAL")
                        .arg(lua_script)
                        .arg(1)
                        .arg("cluster_leader_lock")
                        .arg(self.local_node_id.to_string())
                        .arg(10)
                        .query_async(&mut conn)
                        .await;

                    if result.unwrap_or(0) == 1 {
                        leader_id = Some(self.local_node_id);
                    }
                } else {
                    // Otherwise, try to snatch the lock if the previous leader let it expire.
                    let acquired: bool = redis::cmd("SET")
                        .arg("cluster_leader_lock")
                        .arg(self.local_node_id.to_string())
                        .arg("NX")
                        .arg("EX")
                        .arg(10)
                        .query_async(&mut conn)
                        .await
                        .unwrap_or(false);

                    if acquired {
                        leader_id = Some(self.local_node_id);
                    } else if let Some(current_leader_str) = current_leader {
                        if let Ok(parsed) = Uuid::parse_str(&current_leader_str) {
                            leader_id = Some(parsed);
                        }
                    }
                }
            }
        }

        let leader = if let Some(id) = leader_id {
            nodes
                .clone()
                .into_iter()
                .find(|n| n.id == id)
                .unwrap_or_else(|| {
                    nodes
                        .clone()
                        .into_iter()
                        .min_by_key(|n| n.id)
                        .expect("At least one node exists")
                })
        } else {
            nodes
                .clone()
                .into_iter()
                .min_by_key(|n| n.id)
                .expect("At least one node exists")
        };

        *self.leader_id.write().await = Some(leader.id);

        for node in self.discovery.get_all_nodes() {
            let is_leader = node.id == leader.id;
            let mut updated = node.clone();
            updated.role = if is_leader {
                NodeRole::Leader
            } else {
                NodeRole::Follower
            };
            self.discovery.register_node(updated);
        }

        tracing::info!("Leader elected: {}", leader.id);
        Ok(())
    }

    pub async fn is_leader(&self) -> bool {
        let leader_id = self.leader_id.read().await;
        *leader_id == Some(self.local_node_id)
    }

    pub async fn get_leader(&self) -> Option<ClusterNode> {
        let leader_id = self.leader_id.read().await;
        leader_id.and_then(|id| self.discovery.get_node(id))
    }

    pub async fn step_down(&self) -> anyhow::Result<()> {
        if self.is_leader().await {
            *self.leader_id.write().await = None;
            self.elect_leader().await?;
        }
        Ok(())
    }

    pub async fn on_node_join(&self, node: ClusterNode) -> anyhow::Result<()> {
        self.discovery.register_node(node);
        self.elect_leader().await?;
        Ok(())
    }

    pub async fn on_node_leave(&self, node_id: Uuid) -> anyhow::Result<()> {
        self.discovery.unregister_node(node_id);

        if let Some(leader) = self.get_leader().await {
            if leader.id == node_id {
                self.elect_leader().await?;
            }
        }
        Ok(())
    }
}
