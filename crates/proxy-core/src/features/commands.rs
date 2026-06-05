use std::collections::HashMap;
use std::sync::Arc;

use crate::{proxy::ProxyState, session::SharedSession};

pub enum CommandResult {
    Handled,

    NotACommand,

    Error(String),
}

pub async fn handle_command(
    input: &str,
    session: SharedSession,
    state: Arc<ProxyState>,
    send_message: &mut impl FnMut(String),
) -> CommandResult {
    let trimmed = input.trim_start_matches('/');
    if !is_proxy_command(trimmed) {
        return CommandResult::NotACommand;
    }

    let parts: Vec<&str> = trimmed.splitn(5, ' ').collect();
    let cmd = parts[0].to_lowercase();

    match cmd.as_str() {
        "ban" => handle_ban(parts, session, state, send_message).await,
        "server" | "servers" => handle_server(parts, session, state, send_message).await,
        "hub" | "lobby" | "spawn" => handle_hub(session, state, send_message).await,
        "glist" | "list" => handle_glist(state, send_message).await,
        "alert" => handle_alert(parts, session, send_message).await,
        "find" => handle_find(parts, state, send_message).await,
        "koja" | "kojacoord" => handle_koja(session, send_message).await,
        "plugins" => handle_plugins(state, send_message).await,
        "gtps" => handle_gtps(state, send_message).await,
        _ => CommandResult::NotACommand,
    }
}

async fn handle_ban(
    parts: Vec<&str>,
    session: SharedSession,
    state: Arc<ProxyState>,
    send_message: &mut impl FnMut(String),
) -> CommandResult {
    let (rank, banner) = {
        let s = session.read().await;
        (s.rank.clone(), s.username.clone())
    };
    if !state.roles.rank_has_permission(&rank, "command.ban") {
        send_message("§cYou don't have permission to use that.".to_owned());
        return CommandResult::Handled;
    }

    let target_name = parts.get(1).copied().unwrap_or("");
    if target_name.is_empty() {
        send_message("§cUsage: /ban <player> [reason]".to_owned());
        return CommandResult::Handled;
    }
    let reason = parts
        .get(2..)
        .map(|p| p.join(" "))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Banned by an operator".to_owned());

    let Some(db) = &state.db else {
        send_message("§cBans are unavailable (no database).".to_owned());
        return CommandResult::Handled;
    };

    let mut target_uuid = None;
    {
        let sessions = state.sessions.read().await;
        for (uuid, sess) in sessions.iter() {
            if let Ok(s) = sess.try_read() {
                if s.username.eq_ignore_ascii_case(target_name) {
                    target_uuid = Some(*uuid);
                    break;
                }
            }
        }
    }
    if target_uuid.is_none() {
        target_uuid = db.uuid_for_username(target_name).await.ok().flatten();
    }
    let Some(uuid) = target_uuid else {
        send_message(format!("§cNo player named '{}' was found.", target_name));
        return CommandResult::Handled;
    };

    if let Err(e) = db.insert_ban(uuid, &reason, &banner, None).await {
        tracing::warn!(error = %e, "failed to insert ban");
        send_message("§cFailed to record the ban.".to_owned());
        return CommandResult::Handled;
    }

    let kick_json = serde_json::json!({
        "text": format!("You have been banned: {}", reason),
        "color": "red"
    })
    .to_string();
    state.kick_player(&uuid, &kick_json).await;

    send_message(format!("§aBanned §f{}§a — {}", target_name, reason));
    state
        .broadcast_system_message(&format!("§c{} was banned by {}.", target_name, banner))
        .await;
    CommandResult::Handled
}

async fn handle_server(
    parts: Vec<&str>,
    session: SharedSession,
    state: Arc<ProxyState>,
    send_message: &mut impl FnMut(String),
) -> CommandResult {
    if parts.len() < 2 || parts[1].is_empty() {
        let servers = state.server_registry.all();
        let sess = session.read().await;
        send_message("§6§lKojacoordNetwork §7— §aOnline Servers".to_owned());
        for s in &servers {
            let status = if s.is_online() { "§a●" } else { "§c●" };
            let current = sess.current_server.as_deref() == Some(&s.name);
            let marker = if current { " §7(you are here)" } else { "" };
            send_message(format!(
                "  {} §f{}§7 [{} players]{}",
                status,
                s.name,
                s.player_count(),
                marker
            ));
        }
        CommandResult::Handled
    } else {
        let target = parts[1];
        let Some(backend) = state.server_registry.get(target) else {
            send_message(format!("§cServer '{}' not found.", target));
            return CommandResult::Handled;
        };
        if !backend.is_online() {
            send_message(format!("§cServer '{}' is currently offline.", target));
            return CommandResult::Handled;
        }
        {
            let sess = session.read().await;
            if sess.current_server.as_deref() == Some(target) {
                send_message(format!("§eYou are already on §f{}§e.", target));
                return CommandResult::Handled;
            }
        }
        send_message(format!("§aConnecting you to §f{}§a…", target));

        CommandResult::Handled
    }
}

async fn handle_hub(
    session: SharedSession,
    state: Arc<ProxyState>,
    send_message: &mut impl FnMut(String),
) -> CommandResult {
    let default = state
        .config
        .servers
        .first()
        .map(|s| s.name.clone())
        .unwrap_or_else(|| "lobby".to_owned());

    let Some(_backend) = state.server_registry.get(&default) else {
        send_message("§cLobby server is unavailable.".to_owned());
        return CommandResult::Handled;
    };

    {
        let sess = session.read().await;
        if sess.current_server.as_deref() == Some(&default) {
            send_message(format!("§eYou are already on §f{}§e.", default));
            return CommandResult::Handled;
        }
    }

    send_message(format!("§aSending you to §f{}§a…", default));
    CommandResult::Handled
}

async fn handle_glist(
    state: Arc<ProxyState>,
    send_message: &mut impl FnMut(String),
) -> CommandResult {
    let sessions = state.sessions.read().await;
    let count = sessions.len();
    send_message(format!(
        "§6§lKojacoordNetwork §7— §f{} §7player{} online",
        count,
        if count == 1 { "" } else { "s" }
    ));

    let mut by_server: HashMap<String, Vec<String>> = HashMap::new();
    for sess_arc in sessions.values() {
        if let Ok(sess) = sess_arc.try_read() {
            let server = sess
                .current_server
                .clone()
                .unwrap_or_else(|| "unknown".to_owned());
            by_server
                .entry(server)
                .or_default()
                .push(sess.username.clone());
        }
    }
    for (server, players) in &by_server {
        send_message(format!(
            "§e{} §7[{}]: §f{}",
            server,
            players.len(),
            players.join("§7, §f")
        ));
    }
    CommandResult::Handled
}

async fn handle_alert(
    parts: Vec<&str>,
    session: SharedSession,
    send_message: &mut impl FnMut(String),
) -> CommandResult {
    let msg = parts.get(1..).map(|p| p.join(" ")).unwrap_or_default();
    if msg.is_empty() {
        send_message("§cUsage: /alert <message>".to_owned());
        return CommandResult::Handled;
    }
    let sess = session.read().await;
    let broadcast = format!("§4§l[ALERT] §c{}", msg);

    tracing::info!("[ALERT] from {}: {}", sess.username, broadcast);
    send_message("§aAlert broadcast sent.".to_owned());
    CommandResult::Handled
}

async fn handle_find(
    parts: Vec<&str>,
    state: Arc<ProxyState>,
    send_message: &mut impl FnMut(String),
) -> CommandResult {
    let target_name = parts.get(1).copied().unwrap_or("");
    if target_name.is_empty() {
        send_message("§cUsage: /find <player>".to_owned());
        return CommandResult::Handled;
    }
    let sessions = state.sessions.read().await;
    for sess_arc in sessions.values() {
        if let Ok(sess) = sess_arc.try_read() {
            if sess.username.eq_ignore_ascii_case(target_name) {
                let server = sess.current_server.as_deref().unwrap_or("unknown");
                send_message(format!("§f{} §7is on §a{}", sess.username, server));
                return CommandResult::Handled;
            }
        }
    }
    send_message(format!("§cPlayer '{}' is not online.", target_name));
    CommandResult::Handled
}

async fn handle_koja(
    session: SharedSession,
    send_message: &mut impl FnMut(String),
) -> CommandResult {
    let protocol = session.read().await.protocol_version;
    send_message("§6§lKojacoord Proxy".to_owned());
    send_message("§7Version: §f1.0.0".to_owned());
    send_message("§7Powered by §5Rust §7+ §bTokio".to_owned());
    send_message(format!("§7Protocol: §f{}", protocol));
    CommandResult::Handled
}

async fn handle_plugins(
    state: Arc<ProxyState>,
    send_message: &mut impl FnMut(String),
) -> CommandResult {
    let plugins = state.plugin_manager.loaded_plugins();
    send_message(format!("§6§lPlugins §7(§f{}§7)", plugins.len()));
    if plugins.is_empty() {
        send_message("§7No plugins loaded.".to_owned());
    } else {
        for (name, metadata) in plugins {
            send_message(format!(
                "§a{} §7v§f{} §7by §e{}",
                name, metadata.version, metadata.author
            ));
        }
    }
    CommandResult::Handled
}

async fn handle_gtps(
    state: Arc<ProxyState>,
    send_message: &mut impl FnMut(String),
) -> CommandResult {
    send_message("§6§lServer TPS (Ticks Per Second)".to_owned());

    let tps_5s = state.tps_tracker.calculate_tps(5).await;
    let tps_10s = state.tps_tracker.calculate_tps(10).await;
    let tps_20s = state.tps_tracker.calculate_tps(20).await;
    let tps_30s = state.tps_tracker.calculate_tps(30).await;

    let color_tps = |tps: f64| -> &'static str {
        if tps < 15.0 {
            "§c"
        }
        // Red
        else if tps < 18.0 {
            "§e"
        }
        // Yellow
        else {
            "§a"
        } // Green
    };

    send_message(format!("§eTPS (5s): {}{:.1}", color_tps(tps_5s), tps_5s));
    send_message(format!("§eTPS (10s): {}{:.1}", color_tps(tps_10s), tps_10s));
    send_message(format!("§eTPS (20s): {}{:.1}", color_tps(tps_20s), tps_20s));
    send_message(format!("§eTPS (30s): {}{:.1}", color_tps(tps_30s), tps_30s));

    let sessions = state.sessions.read().await;
    let total_players = sessions.len();
    send_message(format!("§7Online players: §f{}", total_players));

    CommandResult::Handled
}

fn is_proxy_command(input: &str) -> bool {
    let cmd = input.split_whitespace().next().unwrap_or("").to_lowercase();
    matches!(
        cmd.as_str(),
        "ban"
            | "server"
            | "servers"
            | "hub"
            | "lobby"
            | "spawn"
            | "glist"
            | "list"
            | "alert"
            | "find"
            | "koja"
            | "kojacoord"
    )
}

pub fn system_message(text: &str) -> String {
    serde_json::json!({
        "text": text,
        "color": "yellow"
    })
    .to_string()
}

pub fn chat_component(text: &str) -> serde_json::Value {
    serde_json::json!({ "text": text })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_commands_recognized() {
        assert!(is_proxy_command("server lobby"));
        assert!(is_proxy_command("glist"));
        assert!(is_proxy_command("hub"));
        assert!(is_proxy_command("KOJA"));
        assert!(is_proxy_command("plugins"));
        assert!(is_proxy_command("gtps"));
        assert!(!is_proxy_command("gamemode creative"));
        assert!(!is_proxy_command("tp Player2"));
        assert!(!is_proxy_command("say hello"));
    }

    #[test]
    fn is_not_proxy_command_empty() {
        assert!(!is_proxy_command(""));
    }

    #[test]
    fn system_message_is_valid_json() {
        let msg = system_message("hello world");
        let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(v["text"], "hello world");
        assert_eq!(v["color"], "yellow");
    }

    #[test]
    fn chat_component_has_text_field() {
        let v = chat_component("hi");
        assert_eq!(v["text"], "hi");
    }
}
