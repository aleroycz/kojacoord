use crate::api::{
    PacketData, PacketEvent, PacketHookResult, Plugin, PluginContext, PluginEvent, PluginMetadata,
    PluginResponse,
};
use crate::loader::PluginLoader;
use crate::sandbox::{apply_sandbox, SandboxConfig};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

/// A loaded plugin shared across the proxy. The `Mutex` provides the interior
/// mutability the `Plugin` trait requires (`handle_event`/`on_*` take `&mut self`)
/// while still allowing the instance to be shared between tasks.
pub type SharedPlugin = Arc<Mutex<Box<dyn Plugin>>>;

pub struct PluginManager {
    loader: PluginLoader,
    plugins: HashMap<String, (SharedPlugin, PluginMetadata)>,
    plugin_configs: HashMap<String, PluginContext>,
    packet_hooks: Arc<RwLock<Vec<PacketEvent>>>,
    sandbox_enabled: bool,
    sandbox_config: SandboxConfig,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            loader: PluginLoader::new(),
            plugins: HashMap::new(),
            plugin_configs: HashMap::new(),
            packet_hooks: Arc::new(RwLock::new(Vec::new())),
            sandbox_enabled: true,
            sandbox_config: SandboxConfig::default(),
        }
    }

    pub fn enable_sandbox(&mut self, enabled: bool) {
        self.sandbox_enabled = enabled;
        if enabled {
            if let Err(e) = apply_sandbox(&self.sandbox_config) {
                log::error!("Failed to apply sandbox: {}", e);
            }
        }
    }

    pub fn set_sandbox_config(&mut self, config: SandboxConfig) {
        self.sandbox_config = config;
        if self.sandbox_enabled {
            if let Err(e) = apply_sandbox(&self.sandbox_config) {
                log::error!("Failed to apply updated sandbox config: {}", e);
            }
        }
    }

    pub fn load_plugin<P: AsRef<Path>>(
        &mut self,
        path: P,
        config: HashMap<String, String>,
    ) -> anyhow::Result<PluginMetadata> {
        let path = path.as_ref();
        let plugin_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let context = PluginContext {
            plugin_id: plugin_name.clone(),
            version: "1.0.0".to_string(),
            config,
        };

        let (mut plugin, metadata) = self.loader.load_plugin(path, &context)?;

        if metadata.name != plugin_name {
            log::warn!(
                "Plugin name '{}' in metadata doesn't match filename '{}'",
                metadata.name,
                plugin_name
            );
        }

        // Activate the plugin and collect its packet hooks now, while we still
        // own the Box exclusively, so the hooks take effect in `process_packet`.
        if let Err(e) = plugin.on_enable() {
            log::warn!("Plugin '{}' on_enable failed: {}", metadata.name, e);
        }
        let hooks = plugin.register_packet_hooks();
        if !hooks.is_empty() {
            let count = hooks.len();
            self.packet_hooks
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .extend(hooks);
            log::info!(
                "Registered {} packet hook(s) from plugin '{}'",
                count,
                metadata.name
            );
        }

        self.plugins.insert(
            plugin_name.clone(),
            (Arc::new(Mutex::new(plugin)), metadata.clone()),
        );
        self.plugin_configs.insert(plugin_name.clone(), context);

        log::info!(
            "Loaded plugin: {} v{} by {}",
            metadata.name,
            metadata.version,
            metadata.author
        );
        Ok(metadata)
    }

    pub fn load_plugins_from_dir<P: AsRef<Path>>(
        &mut self,
        dir: P,
        configs: HashMap<String, HashMap<String, String>>,
    ) -> anyhow::Result<()> {
        let dir = dir.as_ref();

        // Prevent path traversal attacks by rejecting paths containing '..'.
        if dir
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(anyhow::anyhow!("Invalid input: {}", dir.display()));
        }

        if !dir.exists() {
            log::warn!("Plugin directory does not exist: {:?}", dir);
            return Ok(());
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path
                .extension()
                .is_some_and(|ext| ext == "dll" || ext == "so" || ext == "dylib")
            {
                let plugin_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                let config = configs.get(&plugin_name).cloned().unwrap_or_default();

                if let Err(e) = self.load_plugin(&path, config) {
                    log::error!("Failed to load plugin {:?}: {}", path, e);
                }
            }
        }

        Ok(())
    }

    pub fn unload_plugin(&mut self, name: &str) -> anyhow::Result<PluginMetadata> {
        if let Some((plugin, metadata)) = self.plugins.remove(name) {
            // Run lifecycle teardown before dropping the instance.
            {
                let mut guard = plugin.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(e) = guard.on_disable() {
                    log::warn!("Plugin '{}' on_disable failed: {}", name, e);
                }
                if let Err(e) = guard.on_unload() {
                    log::warn!("Plugin '{}' on_unload failed: {}", name, e);
                }
            }

            self.plugin_configs.remove(name);

            self.packet_hooks
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .clear();

            log::info!("Unloaded plugin: {}", name);
            return Ok(metadata);
        }
        Err(anyhow::anyhow!("Plugin not found: {}", name))
    }

    pub fn unload_all(&mut self) {
        for name in self.plugins.keys().cloned().collect::<Vec<String>>() {
            let _ = self.unload_plugin(&name);
        }
        self.loader.unload_all();
    }

    /// Deliver an event to every loaded plugin's `handle_event` and collect the
    /// non-`None` responses for the caller to act on. Each plugin is locked only
    /// for the duration of its handler.
    pub fn broadcast_event(&self, event: &PluginEvent) -> Vec<PluginResponse> {
        let mut responses = Vec::new();

        for (name, (plugin, _)) in &self.plugins {
            let mut guard = plugin.lock().unwrap_or_else(|e| e.into_inner());
            match guard.handle_event(event) {
                Ok(Some(response)) => responses.push(response),
                Ok(None) => {},
                Err(e) => log::error!("Plugin '{}' handle_event error: {}", name, e),
            }
        }

        responses
    }

    pub fn process_packet(&self, packet: &PacketData) -> PacketHookResult {
        let hooks = self.packet_hooks.read().unwrap_or_else(|e| e.into_inner());

        for hook in hooks.iter() {
            if hook.matches(packet) {
                match hook.execute(packet) {
                    Ok(PacketHookResult::Drop) => return PacketHookResult::Drop,
                    Ok(PacketHookResult::Replace { packet_id, data }) => {
                        return PacketHookResult::Replace { packet_id, data };
                    },
                    Ok(PacketHookResult::Modify(data)) => {
                        let mut modified_packet = packet.clone();
                        modified_packet.data = data;
                        return self.process_packet(&modified_packet);
                    },
                    Ok(PacketHookResult::Forward) => continue,
                    Err(e) => {
                        log::error!("Packet hook error: {}", e);
                        continue;
                    },
                }
            }
        }

        PacketHookResult::Forward
    }

    pub fn loaded_plugins(&self) -> Vec<(String, PluginMetadata)> {
        self.plugins
            .iter()
            .map(|(name, (_, metadata))| (name.clone(), metadata.clone()))
            .collect()
    }

    pub fn get_plugin_metadata(&self, name: &str) -> Option<PluginMetadata> {
        self.plugins.get(name).map(|(_, metadata)| metadata.clone())
    }

    pub fn is_loaded(&self, name: &str) -> bool {
        self.plugins.contains_key(name)
    }

    pub fn get_packet_hooks(&self) -> Vec<HookInfo> {
        let hooks = self.packet_hooks.read().unwrap_or_else(|e| e.into_inner());
        hooks
            .iter()
            .map(|hook| HookInfo {
                packet_id: hook.filter().packet_id,
                protocol_version: hook.filter().protocol_version,
                direction: format!("{:?}", hook.filter().direction),
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct HookInfo {
    pub packet_id: Option<i32>,
    pub protocol_version: Option<u32>,
    pub direction: String,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}
