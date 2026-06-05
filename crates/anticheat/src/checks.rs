use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    alert_system::AlertSystem,
    bridge::BridgeClient,
    mod_compatibility::ModCompatibility,
    player_state::PlayerAnticheatState,
    violation::{CheckCategory, Violation},
};
use kojacoord_config::AnticheatConfig;

const SPEED_MARGIN: f64 = 2.0;
const SPEED_EPSILON: f64 = 0.1;
const MIN_SPEED_VL: u32 = 5;
const MIN_FLIGHT_VL: u32 = 5;
const MIN_NOFALL_VL: u32 = 5;
const MIN_COMBAT_VL: u32 = 3;
const MIN_AIMBOT_VL: u32 = 4;
const MIN_AUTOTOOL_VL: u32 = 3;
const MIN_SCAFFOLD_VL: u32 = 5;

pub struct AnticheatEngine {
    config: Arc<RwLock<AnticheatConfig>>,
    states: Arc<DashMap<Uuid, PlayerAnticheatState>>,
    bridge: Option<BridgeClient>,
    alert_system: AlertSystem,
    mod_compat: ModCompatibility,
}

impl AnticheatEngine {
    pub fn new(config: AnticheatConfig) -> Self {
        let bridge = config
            .bridge_endpoint
            .as_ref()
            .map(|ep| BridgeClient::new(ep.clone()));
        let alert_system = AlertSystem::new(crate::alert_system::AlertConfig::default())
            .with_name("Kojacoord Guardian".to_string());
        let mod_compat = ModCompatibility::new(true, false);

        Self {
            config: Arc::new(RwLock::new(config)),
            states: Arc::new(DashMap::new()),
            bridge,
            alert_system,
            mod_compat,
        }
    }

    pub async fn reload_config(&self, new_config: AnticheatConfig) {
        *self.config.write().await = new_config;
    }

    pub fn get_alert_system(&self) -> &AlertSystem {
        &self.alert_system
    }

    pub fn get_mod_compatibility(&self) -> &ModCompatibility {
        &self.mod_compat
    }

    pub async fn register_mod_brand(&self, uuid: Uuid, brand: String) {
        let mut state = self.states.entry(uuid).or_default();

        let detected = self.mod_compat.detect_mods_from_brand(&brand);
        state.detected_mods = detected.clone();
        state.is_modded_client = !detected.is_empty();

        for mod_name in &detected {
            if self.mod_compat.is_trusted_mod(mod_name) {
                state.trusted_mods.push(mod_name.clone());
            }
        }
    }

    pub async fn check_movement(
        &self,
        uuid: Uuid,
        x: f64,
        y: f64,
        z: f64,
        on_ground: bool,
    ) -> Option<Violation> {
        let config = self.config.read().await;
        if !config.enabled {
            return None;
        }
        let mut state = self.states.entry(uuid).or_default();

        let dx = x - state.last_x;
        let dy = y - state.last_y;
        let dz = z - state.last_z;
        let speed = (dx * dx + dz * dz).sqrt();

        state.last_x = x;
        state.last_y = y;
        state.last_z = z;

        let boost = state
            .active_effects
            .iter()
            .find(|e| e.effect_id == 1)
            .map(|e| 0.2 * f64::from(e.amplifier + 1))
            .unwrap_or(0.0);

        let effective = config.max_speed_blocks_per_tick * SPEED_MARGIN * (1.0 + boost);

        let threshold = config.max_speed_blocks_per_tick * (1.0 + boost);

        let is_flying = !on_ground && dy > 0.0 && state.air_ticks > 3;
        let no_fall = !on_ground && state.air_ticks > 10 && dy <= -0.5;

        if on_ground {
            state.last_ground_time = Instant::now();
            state.air_ticks = 0;
        } else {
            state.air_ticks += 1;
        }

        state.on_ground = on_ground;
        state.last_move = Instant::now();

        let should_suppress_speed = self.mod_compat.should_suppress_check(&state, "Speed");
        let should_suppress_flight = self.mod_compat.should_suppress_check(&state, "Flight");
        let should_suppress_nofall = self.mod_compat.should_suppress_check(&state, "NoFall");

        let mut violation_to_report = None;

        if speed > effective + SPEED_EPSILON && !should_suppress_speed {
            let count = self.increment_violation_count(&mut state, "Speed");
            if count >= MIN_SPEED_VL {
                violation_to_report = Some(Violation {
                    player_uuid: uuid,
                    check_name: "Speed".into(),
                    check_category: CheckCategory::Movement,
                    value: speed,
                    threshold,
                    timestamp: chrono::Utc::now(),
                    server_id: None,
                    suppressed: false,
                });
            }
        } else {
            self.decay_violation(&mut state, "Speed");
        }

        if violation_to_report.is_none() && is_flying && !should_suppress_flight {
            let count = self.increment_violation_count(&mut state, "Flight");
            if count >= MIN_FLIGHT_VL {
                violation_to_report = Some(Violation {
                    player_uuid: uuid,
                    check_name: "Flight".into(),
                    check_category: CheckCategory::Movement,
                    value: state.air_ticks as f64,
                    threshold: 3.0,
                    timestamp: chrono::Utc::now(),
                    server_id: None,
                    suppressed: false,
                });
            }
        } else if violation_to_report.is_none() {
            self.decay_violation(&mut state, "Flight");
        }

        if violation_to_report.is_none() && no_fall && !should_suppress_nofall {
            let count = self.increment_violation_count(&mut state, "NoFall");
            if count >= MIN_NOFALL_VL {
                violation_to_report = Some(Violation {
                    player_uuid: uuid,
                    check_name: "NoFall".into(),
                    check_category: CheckCategory::Movement,
                    value: state.air_ticks as f64,
                    threshold: 10.0,
                    timestamp: chrono::Utc::now(),
                    server_id: None,
                    suppressed: false,
                });
            }
        } else if violation_to_report.is_none() {
            self.decay_violation(&mut state, "NoFall");
        }

        drop(state);

        if let Some(v) = violation_to_report {
            if let Some(bridge) = &self.bridge {
                let _ = bridge.report(&v).await;
            }
            return Some(v);
        }

        None
    }

    pub async fn check_attack(
        &self,
        uuid: Uuid,
        target_distance: Option<f64>,
    ) -> Option<Violation> {
        let config = self.config.read().await;
        if !config.enabled {
            return None;
        }
        let mut state = self.states.entry(uuid).or_default();

        let now = Instant::now();
        state.recent_attacks.push_back(now);
        while let Some(&front) = state.recent_attacks.front() {
            if now.duration_since(front).as_secs_f64() > 1.0 {
                state.recent_attacks.pop_front();
            } else {
                break;
            }
        }

        let cps = state.recent_attacks.len() as f64;
        let threshold = f64::from(config.max_cps);

        let should_suppress = self.mod_compat.should_suppress_check(&state, "Killaura");

        let mut violation_to_report = None;

        if cps > threshold && !should_suppress {
            let count = self.increment_violation_count(&mut state, "Killaura");
            if count >= MIN_COMBAT_VL {
                violation_to_report = Some(Violation {
                    player_uuid: uuid,
                    check_name: "Killaura".into(),
                    check_category: CheckCategory::Combat,
                    value: cps,
                    threshold,
                    timestamp: chrono::Utc::now(),
                    server_id: None,
                    suppressed: false,
                });
            }
        } else {
            self.decay_violation(&mut state, "Killaura");
        }

        if violation_to_report.is_none() {
            if let Some(distance) = target_distance {
                let reach_threshold = 4.5;
                let should_suppress_reach = self.mod_compat.should_suppress_check(&state, "Reach");

                if distance > reach_threshold && !should_suppress_reach {
                    let count = self.increment_violation_count(&mut state, "Reach");
                    if count >= MIN_COMBAT_VL {
                        violation_to_report = Some(Violation {
                            player_uuid: uuid,
                            check_name: "Reach".into(),
                            check_category: CheckCategory::Combat,
                            value: distance,
                            threshold: reach_threshold,
                            timestamp: chrono::Utc::now(),
                            server_id: None,
                            suppressed: false,
                        });
                    }
                } else {
                    self.decay_violation(&mut state, "Reach");
                }
            }
        }

        drop(state);

        if let Some(v) = violation_to_report {
            if let Some(bridge) = &self.bridge {
                let _ = bridge.report(&v).await;
            }
            return Some(v);
        }

        None
    }

    pub async fn check_timer(&self, uuid: Uuid) -> Option<Violation> {
        let config = self.config.read().await;
        if !config.enabled {
            return None;
        }
        let mut state = self.states.entry(uuid).or_default();

        let now = Instant::now();
        state.packets_sent_in_second += 1;

        let mut violation_to_report = None;

        if now.duration_since(state.last_packet_reset).as_secs() >= 1 {
            let pps = state.packets_sent_in_second as f64;
            let normal_pps = 20.0;
            let threshold = normal_pps * 1.5;

            state.packets_sent_in_second = 0;
            state.last_packet_reset = now;

            let should_suppress = self.mod_compat.should_suppress_check(&state, "Timer");

            if pps > threshold && !should_suppress {
                self.increment_violation_count(&mut state, "Timer");
                violation_to_report = Some(Violation {
                    player_uuid: uuid,
                    check_name: "Timer".into(),
                    check_category: CheckCategory::Network,
                    value: pps,
                    threshold,
                    timestamp: chrono::Utc::now(),
                    server_id: None,
                    suppressed: false,
                });
            }
        }

        drop(state);

        if let Some(v) = violation_to_report {
            if let Some(bridge) = &self.bridge {
                let _ = bridge.report(&v).await;
            }
            return Some(v);
        }

        None
    }

    pub async fn check_autosprint(
        &self,
        uuid: Uuid,
        sprinting: bool,
        food_level: u32,
    ) -> Option<Violation> {
        let config = self.config.read().await;
        if !config.enabled {
            return None;
        }
        let mut state = self.states.entry(uuid).or_default();

        let mut violation_to_report = None;

        if sprinting && food_level < 6 {
            let should_suppress = self.mod_compat.should_suppress_check(&state, "AutoSprint");

            if !should_suppress {
                self.increment_violation_count(&mut state, "AutoSprint");
                violation_to_report = Some(Violation {
                    player_uuid: uuid,
                    check_name: "AutoSprint".into(),
                    check_category: CheckCategory::Player,
                    value: food_level as f64,
                    threshold: 6.0,
                    timestamp: chrono::Utc::now(),
                    server_id: None,
                    suppressed: false,
                });
            }
        }

        drop(state);

        if let Some(v) = violation_to_report {
            if let Some(bridge) = &self.bridge {
                let _ = bridge.report(&v).await;
            }
            return Some(v);
        }

        None
    }

    fn increment_violation_count(&self, state: &mut PlayerAnticheatState, check_name: &str) -> u32 {
        let entry = state
            .check_violations
            .entry(check_name.to_string())
            .or_insert(0);
        *entry += 1;
        *entry
    }

    fn decay_violation(&self, state: &mut PlayerAnticheatState, check_name: &str) {
        if let Some(c) = state.check_violations.get_mut(check_name) {
            *c = c.saturating_sub(1);
        }
    }

    pub async fn get_violation_count(&self, uuid: &Uuid, check_name: &str) -> u32 {
        self.states
            .get(uuid)
            .and_then(|s| s.check_violations.get(check_name).copied())
            .unwrap_or(0)
    }

    pub async fn player_quit(&self, uuid: &Uuid) {
        self.states.remove(uuid);
    }

    pub async fn get_player_state(&self, uuid: &Uuid) -> Option<PlayerAnticheatState> {
        self.states.get(uuid).map(|r| r.clone())
    }

    pub async fn check_aimbot(
        &self,
        uuid: Uuid,
        yaw: f64,
        pitch: f64,
        target_distance: f64,
    ) -> Option<Violation> {
        let config = self.config.read().await;
        if !config.enabled {
            return None;
        }
        let mut state = self.states.entry(uuid).or_default();

        let now = Instant::now();
        let time_since_last_check: Duration = now.duration_since(state.last_aim_check);
        state.last_aim_check = now;

        if time_since_last_check.as_millis() < 50 {
            return None;
        }

        let yaw_delta = (yaw - state.last_yaw).abs();
        let pitch_delta = (pitch - state.last_pitch).abs();
        let rotation_delta = (yaw_delta.powi(2) + pitch_delta.powi(2)).sqrt();

        state.last_yaw = yaw;
        state.last_pitch = pitch;

        let should_suppress = self.mod_compat.should_suppress_check(&state, "Aimbot");

        let max_rotation_per_tick = 180.0;
        let min_snapping_threshold = 0.1;

        let mut violation_to_report = None;

        if (rotation_delta > max_rotation_per_tick
            || (rotation_delta < min_snapping_threshold && target_distance > 5.0))
            && !should_suppress
        {
            let count = self.increment_violation_count(&mut state, "Aimbot");
            if count >= MIN_AIMBOT_VL {
                violation_to_report = Some(Violation {
                    player_uuid: uuid,
                    check_name: "Aimbot".into(),
                    check_category: CheckCategory::Combat,
                    value: rotation_delta,
                    threshold: max_rotation_per_tick,
                    timestamp: chrono::Utc::now(),
                    server_id: None,
                    suppressed: false,
                });
            }
        } else {
            self.decay_violation(&mut state, "Aimbot");
        }

        drop(state);

        if let Some(v) = violation_to_report {
            if let Some(bridge) = &self.bridge {
                let _ = bridge.report(&v).await;
            }
            return Some(v);
        }

        None
    }

    pub async fn check_autotool(
        &self,
        uuid: Uuid,
        slot_change_count: u32,
        time_delta_ms: u64,
    ) -> Option<Violation> {
        let config = self.config.read().await;
        if !config.enabled {
            return None;
        }
        let mut state = self.states.entry(uuid).or_default();

        let should_suppress = self.mod_compat.should_suppress_check(&state, "AutoTool");

        let min_switch_time_ms = 50;
        let switches_per_second = if time_delta_ms > 0 {
            (slot_change_count as f64) / (time_delta_ms as f64 / 1000.0)
        } else {
            0.0
        };
        let avg_time_per_switch = if slot_change_count > 0 {
            time_delta_ms as f64 / slot_change_count as f64
        } else {
            0.0
        };

        let mut violation_to_report = None;

        if (switches_per_second > 20.0 || avg_time_per_switch < min_switch_time_ms as f64)
            && !should_suppress
        {
            let count = self.increment_violation_count(&mut state, "AutoTool");
            if count >= MIN_AUTOTOOL_VL {
                violation_to_report = Some(Violation {
                    player_uuid: uuid,
                    check_name: "AutoTool".into(),
                    check_category: CheckCategory::Player,
                    value: switches_per_second,
                    threshold: 20.0,
                    timestamp: chrono::Utc::now(),
                    server_id: None,
                    suppressed: false,
                });
            }
        } else {
            self.decay_violation(&mut state, "AutoTool");
        }

        drop(state);

        if let Some(v) = violation_to_report {
            if let Some(bridge) = &self.bridge {
                let _ = bridge.report(&v).await;
            }
            return Some(v);
        }

        None
    }

    pub async fn check_scaffold(
        &self,
        uuid: Uuid,
        y: f64,
        on_ground: bool,
        placing: bool,
    ) -> Option<Violation> {
        let config = self.config.read().await;
        if !config.enabled {
            return None;
        }
        let mut state = self.states.entry(uuid).or_default();

        let should_suppress = self.mod_compat.should_suppress_check(&state, "Scaffold");

        let mut violation_to_report = None;

        if placing && !on_ground && state.air_ticks > 2 {
            let height_diff = (y - state.last_y).abs();

            if height_diff < 0.1 && height_diff > 0.0 && !should_suppress {
                state.scaffold_ticks += 1;

                if state.scaffold_ticks >= 10 {
                    let count = self.increment_violation_count(&mut state, "Scaffold");
                    if count >= MIN_SCAFFOLD_VL {
                        violation_to_report = Some(Violation {
                            player_uuid: uuid,
                            check_name: "Scaffold".into(),
                            check_category: CheckCategory::Player,
                            value: state.scaffold_ticks as f64,
                            threshold: 10.0,
                            timestamp: chrono::Utc::now(),
                            server_id: None,
                            suppressed: false,
                        });
                        state.scaffold_ticks = 0;
                    }
                }
            } else {
                state.scaffold_ticks = 0;
            }
        } else {
            state.scaffold_ticks = 0;
            self.decay_violation(&mut state, "Scaffold");
        }

        drop(state);

        if let Some(v) = violation_to_report {
            if let Some(bridge) = &self.bridge {
                let _ = bridge.report(&v).await;
            }
            return Some(v);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn speed_check_flags_fast_movement() {
        let config = AnticheatConfig {
            enabled: true,
            max_speed_blocks_per_tick: 0.5,
            max_cps: 20,
            bridge_endpoint: None,
            store_violations: false,
        };
        let engine = AnticheatEngine::new(config);
        let uuid = Uuid::new_v4();

        let v1 = engine.check_movement(uuid, 0.0, 64.0, 0.0, true).await;
        assert!(v1.is_none());

        let mut last: Option<Violation> = None;
        for i in 0..6 {
            let x = if i % 2 == 0 { 10.0 } else { 0.0 };
            last = engine.check_movement(uuid, x, 64.0, 0.0, false).await;
        }
        let v = last.expect("sustained fast movement should eventually flag");
        assert_eq!(v.check_name, "Speed");
    }

    #[tokio::test]
    async fn speed_check_normal_movement() {
        let config = AnticheatConfig::default();
        let engine = AnticheatEngine::new(config);
        let uuid = Uuid::new_v4();
        engine.check_movement(uuid, 0.0, 64.0, 0.0, true).await;
        let v = engine.check_movement(uuid, 0.2, 64.0, 0.0, true).await;
        assert!(v.is_none());
    }

    #[tokio::test]
    async fn mod_detection_works() {
        let engine = AnticheatEngine::new(AnticheatConfig::default());
        let uuid = Uuid::new_v4();

        engine.register_mod_brand(uuid, "fabric".to_string()).await;
        let state = engine.get_player_state(&uuid).await.unwrap();
        assert!(state.is_modded_client);
        assert!(state
            .detected_mods
            .iter()
            .any(|m| m.contains("trusted:fabric")));
    }

    #[tokio::test]
    async fn cheat_mod_detection_works() {
        let engine = AnticheatEngine::new(AnticheatConfig::default());
        let uuid = Uuid::new_v4();

        engine
            .register_mod_brand(uuid, "wurst-client".to_string())
            .await;
        let state = engine.get_player_state(&uuid).await.unwrap();
        assert!(state.is_modded_client);
        assert!(state.detected_mods.iter().any(|m| m.contains("wurst")));
    }
}
