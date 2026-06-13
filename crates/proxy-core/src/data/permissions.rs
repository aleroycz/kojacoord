//! Roles, permission nodes, and pattern matching.
//!
//! Roles carry display metadata (name, prefix, colour) plus a list
//! of permission nodes ("group.servers.manage", "command.tps", …).
//! Patterns support `*` wildcards à la Bukkit/Vault. Roles are
//! loaded from the database at startup; falls back to a built-in
//! `default` role with no permissions when no DB is configured.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Role {
    pub name: String,
    pub display_name: String,

    pub prefix: String,

    pub color: String,
    pub weight: i32,
    permissions: Vec<String>,
}

impl Role {
    pub fn has_permission(&self, node: &str) -> bool {
        for p in &self.permissions {
            if permission_matches(p, node) {
                if p == "*" {
                    tracing::debug!(role = %self.name, node, "granted via global '*' wildcard permission");
                }
                return true;
            }
        }
        false
    }

    /// Raw permission nodes attached directly to this role (no
    /// inheritance applied).
    pub fn permissions(&self) -> &[String] {
        &self.permissions
    }
}

/// Match a permission `pattern` against a requested `node`.
///
/// Supports:
/// - exact match (`command.ban` == `command.ban`)
/// - global wildcard (`*` matches everything)
/// - hierarchical wildcard (`command.*` matches `command.ban` and
///   `command.sub.node`, but NOT `admin.reload`)
fn permission_matches(pattern: &str, node: &str) -> bool {
    if pattern == "*" || pattern == node {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        // `command.*` matches `command.ban`, `command.x.y`, but not `command`
        // itself nor unrelated roots like `admin.*`.
        return node
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('.'));
    }
    false
}

#[derive(Debug, Clone, Default)]
pub struct RoleRegistry {
    roles: HashMap<String, Role>,
}

impl RoleRegistry {
    pub fn from_rows(rows: Vec<crate::db::RoleRow>) -> Self {
        let roles = rows
            .into_iter()
            .map(|r| {
                let role = Role {
                    name: r.name.clone(),
                    display_name: r.display_name,
                    prefix: r.prefix,
                    color: r.color,
                    weight: r.weight,
                    permissions: r.permissions,
                };
                (r.name.to_uppercase(), role)
            })
            .collect();
        Self { roles }
    }

    pub fn builtin_default() -> Self {
        let mut roles = HashMap::new();
        roles.insert(
            "PLAYER".to_owned(),
            Role {
                name: "PLAYER".to_owned(),
                display_name: "Player".to_owned(),
                prefix: String::new(),
                color: "gray".to_owned(),
                weight: 0,
                permissions: Vec::new(),
            },
        );
        Self { roles }
    }

    pub fn len(&self) -> usize {
        self.roles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
    }

    pub fn get(&self, rank: &str) -> Option<&Role> {
        self.roles.get(&rank.to_uppercase())
    }

    pub fn rank_has_permission(&self, rank: &str, node: &str) -> bool {
        self.get(rank)
            .map(|r| r.has_permission(node))
            .unwrap_or(false)
    }

    pub fn format_chat(&self, rank: &str, name: &str, message: &str) -> String {
        match self.get(rank) {
            Some(role) => {
                let prefix = translate_codes(&role.prefix);
                let color = color_code(&role.color);
                format!("{}§{}{}§f: {}", prefix, color, name, message)
            },
            None => format!("{}: {}", name, message),
        }
    }
}

fn translate_codes(s: &str) -> String {
    s.replace('&', "§")
}

fn color_code(name: &str) -> char {
    match name {
        "black" => '0',
        "dark_blue" => '1',
        "dark_green" => '2',
        "dark_aqua" => '3',
        "dark_red" => '4',
        "dark_purple" => '5',
        "gold" => '6',
        "gray" | "grey" => '7',
        "dark_gray" | "dark_grey" => '8',
        "blue" => '9',
        "green" => 'a',
        "aqua" => 'b',
        "red" => 'c',
        "light_purple" => 'd',
        "yellow" => 'e',
        "white" => 'f',
        _ => 'f',
    }
}

// ---------------------------------------------------------------------
// LuckPerms-shaped permission resolution
// ---------------------------------------------------------------------

use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

/// A single per-user permission node. `value` false is a *negation*
/// (explicitly denies the node). `server` scopes the node to a backend;
/// `None` is global.
#[derive(Debug, Clone)]
pub struct UserNode {
    pub node: String,
    pub value: bool,
    pub server: Option<String>,
}

/// A user's resolved permission overlay (their own nodes, on top of
/// whatever their role/group grants).
#[derive(Debug, Default, Clone)]
pub struct UserPermissions {
    pub nodes: Vec<UserNode>,
}

/// LuckPerms-style permission resolver layered on top of [`RoleRegistry`].
///
/// Resolution order for `has_permission`:
///   1. The user's own nodes (most specific wins; a negation beats a
///      grant at equal specificity). These override groups entirely.
///   2. The user's group (role) nodes, including inherited parent
///      groups (cycle-guarded), via wildcard-aware matching.
///
/// Roles ARE groups — `RoleRegistry` supplies their nodes and display
/// metadata; `group_parents` adds inheritance edges loaded from the
/// `lp_group_parents` table. Per-user nodes live in `lp_user_nodes` and
/// are cached here per online player.
pub struct PermissionService {
    roles: Arc<RoleRegistry>,
    /// child (UPPERCASE) -> parent groups (UPPERCASE).
    group_parents: HashMap<String, Vec<String>>,
    /// Per-online-user node cache, keyed by UUID.
    users: DashMap<Uuid, UserPermissions>,
}

impl PermissionService {
    pub fn new(roles: Arc<RoleRegistry>, parent_edges: Vec<(String, String)>) -> Self {
        let mut group_parents: HashMap<String, Vec<String>> = HashMap::new();
        for (child, parent) in parent_edges {
            group_parents
                .entry(child.to_uppercase())
                .or_default()
                .push(parent.to_uppercase());
        }
        Self {
            roles,
            group_parents,
            users: DashMap::new(),
        }
    }

    /// Cache a user's nodes (called on join after loading from the DB).
    pub fn cache_user(&self, uuid: Uuid, nodes: Vec<UserNode>) {
        self.users.insert(uuid, UserPermissions { nodes });
    }

    /// Drop a user's cached nodes (called on disconnect).
    pub fn evict_user(&self, uuid: &Uuid) {
        self.users.remove(uuid);
    }

    /// Add or update a node in the in-memory cache (persisting to the DB
    /// is the caller's responsibility).
    pub fn set_cached_node(&self, uuid: Uuid, node: UserNode) {
        let mut entry = self.users.entry(uuid).or_default();
        entry
            .nodes
            .retain(|n| !(n.node == node.node && n.server == node.server));
        entry.nodes.push(node);
    }

    /// Resolve whether `uuid` (whose primary group is `rank`) holds
    /// `node` in the optional `server` context.
    pub fn has_permission(
        &self,
        uuid: &Uuid,
        rank: &str,
        node: &str,
        server: Option<&str>,
    ) -> bool {
        // 1. User-specific nodes take precedence over groups.
        if let Some(user) = self.users.get(uuid) {
            if let Some(value) = resolve_user_nodes(&user.nodes, node, server) {
                return value;
            }
        }
        // 2. Group nodes, including inherited parents.
        self.group_grants(&rank.to_uppercase(), node, &mut Vec::new())
    }

    /// Walk a group and its parents (cycle-guarded) checking for a
    /// wildcard-aware match on `node`.
    fn group_grants(&self, group: &str, node: &str, visited: &mut Vec<String>) -> bool {
        if visited.contains(&group.to_string()) {
            return false;
        }
        visited.push(group.to_string());

        if let Some(role) = self.roles.get(group) {
            for p in role.permissions() {
                if permission_matches(p, node) {
                    return true;
                }
            }
        }
        if let Some(parents) = self.group_parents.get(group) {
            for parent in parents {
                if self.group_grants(parent, node, visited) {
                    return true;
                }
            }
        }
        false
    }
}

/// From a user's nodes, return `Some(true/false)` if any node decides
/// `node` for `server`, or `None` if the user has no opinion. An exact
/// match outranks a wildcard match; at equal specificity a negation
/// (false) outranks a grant (true).
fn resolve_user_nodes(nodes: &[UserNode], node: &str, server: Option<&str>) -> Option<bool> {
    let mut exact: Option<bool> = None;
    let mut wildcard: Option<bool> = None;
    for n in nodes {
        // Context gate: a server-scoped node only applies in that server.
        if let Some(ctx) = &n.server {
            if Some(ctx.as_str()) != server {
                continue;
            }
        }
        if n.node == node {
            // Negation wins ties.
            exact = Some(exact.map_or(n.value, |prev| prev && n.value));
        } else if permission_matches(&n.node, node) {
            wildcard = Some(wildcard.map_or(n.value, |prev| prev && n.value));
        }
    }
    exact.or(wildcard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::RoleRow;

    fn registry() -> RoleRegistry {
        RoleRegistry::from_rows(vec![
            RoleRow {
                name: "ADMIN".into(),
                display_name: "Admin".into(),
                prefix: "&c[Admin] ".into(),
                color: "red".into(),
                weight: 100,
                permissions: vec!["*".into()],
            },
            RoleRow {
                name: "PLAYER".into(),
                display_name: "Player".into(),
                prefix: "".into(),
                color: "gray".into(),
                weight: 0,
                permissions: vec![],
            },
        ])
    }

    #[test]
    fn wildcard_grants_all() {
        let r = registry();
        assert!(r.rank_has_permission("ADMIN", "command.ban"));
        assert!(!r.rank_has_permission("PLAYER", "command.ban"));
        assert!(!r.rank_has_permission("UNKNOWN", "command.ban"));
    }

    #[test]
    fn chat_format_has_prefix_and_color() {
        let r = registry();
        let line = r.format_chat("ADMIN", "Fernix", "hi");
        assert!(line.contains("§c[Admin] "));
        assert!(line.contains("Fernix"));
        assert!(line.ends_with("hi"));

        assert_eq!(r.format_chat("NOPE", "Bob", "yo"), "Bob: yo");
    }

    #[test]
    fn case_insensitive_lookup() {
        let r = registry();
        assert!(r.get("admin").is_some());
    }

    #[test]
    fn hierarchical_wildcard_matching() {
        // command.* matches command.ban but not admin.reload
        assert!(permission_matches("command.*", "command.ban"));
        assert!(permission_matches("command.*", "command.sub.node"));
        assert!(!permission_matches("command.*", "admin.reload"));
        // a prefixed wildcard must not match the bare prefix
        assert!(!permission_matches("command.*", "command"));
        // partial-name collision must not match (commandx vs command.*)
        assert!(!permission_matches("command.*", "commandx.ban"));
        // exact and global
        assert!(permission_matches("command.ban", "command.ban"));
        assert!(permission_matches("*", "anything.at.all"));
        assert!(!permission_matches("command.ban", "command.kick"));
    }

    fn service() -> (PermissionService, Uuid) {
        // VIP inherits PLAYER; ADMIN has '*'.
        let roles = Arc::new(RoleRegistry::from_rows(vec![
            RoleRow {
                name: "ADMIN".into(),
                display_name: "Admin".into(),
                prefix: "".into(),
                color: "red".into(),
                weight: 100,
                permissions: vec!["*".into()],
            },
            RoleRow {
                name: "VIP".into(),
                display_name: "VIP".into(),
                prefix: "".into(),
                color: "gold".into(),
                weight: 10,
                permissions: vec!["command.fly".into()],
            },
            RoleRow {
                name: "PLAYER".into(),
                display_name: "Player".into(),
                prefix: "".into(),
                color: "gray".into(),
                weight: 0,
                permissions: vec!["command.spawn".into()],
            },
        ]));
        let svc = PermissionService::new(roles, vec![("VIP".into(), "PLAYER".into())]);
        (svc, Uuid::from_u128(1))
    }

    #[test]
    fn group_inheritance_resolves_parent_nodes() {
        let (svc, uuid) = service();
        // VIP's own node.
        assert!(svc.has_permission(&uuid, "VIP", "command.fly", None));
        // Inherited from PLAYER.
        assert!(svc.has_permission(&uuid, "VIP", "command.spawn", None));
        // Not granted anywhere.
        assert!(!svc.has_permission(&uuid, "VIP", "command.ban", None));
        // ADMIN wildcard.
        assert!(svc.has_permission(&uuid, "ADMIN", "command.ban", None));
    }

    #[test]
    fn user_nodes_override_group_and_negate() {
        let (svc, uuid) = service();
        // Grant an extra node directly to the user.
        svc.cache_user(
            uuid,
            vec![
                UserNode {
                    node: "command.ban".into(),
                    value: true,
                    server: None,
                },
                // Negate an inherited group node.
                UserNode {
                    node: "command.spawn".into(),
                    value: false,
                    server: None,
                },
            ],
        );
        assert!(svc.has_permission(&uuid, "VIP", "command.ban", None));
        // Negation beats the inherited grant.
        assert!(!svc.has_permission(&uuid, "VIP", "command.spawn", None));
    }

    #[test]
    fn server_context_scopes_user_nodes() {
        let (svc, uuid) = service();
        svc.cache_user(
            uuid,
            vec![UserNode {
                node: "command.kit".into(),
                value: true,
                server: Some("lobby".into()),
            }],
        );
        // Only applies on the scoped server.
        assert!(svc.has_permission(&uuid, "PLAYER", "command.kit", Some("lobby")));
        assert!(!svc.has_permission(&uuid, "PLAYER", "command.kit", Some("survival")));
        assert!(!svc.has_permission(&uuid, "PLAYER", "command.kit", None));
    }
}
