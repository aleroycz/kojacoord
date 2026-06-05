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
        self.permissions.iter().any(|p| p == "*" || p == node)
    }
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
}
