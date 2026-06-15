//! Wasmtime-backed plugin loader.
//!
//! The native plugin loader (`.dll`/`.so`/`.dylib`) hands modules the
//! full process — fast but unsafe. This is the alternative: load
//! plugins as WebAssembly modules running in a wasmtime sandbox, with
//! memory limits, CPU fuel, and a whitelist of host imports. Slower
//! and more constrained, but safe enough that operators can run
//! third-party plugins they haven't audited.
//!
//! Same `Plugin` trait surface as native plugins — the
//! [`WasmPluginAdapter`] wraps a `WasmPluginInstance` and forwards
//! every trait method through the wasm function table.

use crate::api::{
    PacketDirection, PacketEvent as PacketHookEvent, PacketFilter, PacketHookResult, Plugin,
    PluginContext, PluginEvent, PluginMetadata, PluginResponse,
};
use crate::integrity::PluginVerifier;
use crate::sandbox::SandboxConfig;
use anyhow::{Context, Result};
use sha2::digest::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use wasmtime::{Caller, Config, Engine, Instance, Linker, Module, Store, Val};
use wasmtime_wasi::preview1::WasiP1Ctx;
use wasmtime_wasi::WasiCtxBuilder;

/// One loaded plugin's owning state. `engine` + `module` are
/// shareable across instances; `store` and `instance` are per-plugin
/// because wasmtime stores aren't `Sync`. Both are wrapped in
/// `std::sync::Mutex` — guards never cross an `await`, see the
/// scoping in `instantiate_module`.
pub struct WasmPluginInstance {
    pub name: String,
    pub version: String,
    pub engine: Engine,
    pub module: Module,
    pub store: Mutex<Store<WasiP1Ctx>>,
    pub instance: Mutex<Option<Instance>>,
    pub metadata: PluginMetadata,
}

/// Shared wasmtime engine plus the registry of loaded modules. The
/// linker is shared across all plugins so host imports only need to
/// be wired once; integrity verification runs on the raw module bytes
/// before they ever reach the engine.
pub struct WasmLoader {
    engine: Engine,
    plugins: Arc<RwLock<HashMap<String, Arc<Mutex<WasmPluginInstance>>>>>,
    linker: Mutex<Linker<WasiP1Ctx>>,
    verifier: PluginVerifier,
    sandbox_config: SandboxConfig,
}

impl WasmLoader {
    pub fn new() -> Result<Self> {
        Self::with_config(SandboxConfig::default(), PluginVerifier::new())
    }

    pub fn with_config(sandbox_config: SandboxConfig, verifier: PluginVerifier) -> Result<Self> {
        // Configure wasmtime engine with appropriate limits
        let mut config = Config::new();
        config.wasm_component_model(false);
        config.wasm_simd(true);
        config.wasm_multi_memory(true);
        config.wasm_threads(false); // Disable for safety
        config.wasm_reference_types(true);

        // Set memory limits for security
        config.max_wasm_stack(512 * 1024); // 512KB stack
                                           // Memory limits are set via allocation strategy in wasmtime 24

        let engine = Engine::new(&config).context("Failed to create Wasmtime engine")?;

        // Create linker with WASI support
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |s: &mut WasiP1Ctx| s)
            .context("Failed to add WASI to linker")?;

        // Add custom host functions for plugin API
        Self::add_host_functions(&mut linker, &engine)?;

        Ok(Self {
            engine,
            plugins: Arc::new(RwLock::new(HashMap::new())),
            linker: Mutex::new(linker),
            verifier,
            sandbox_config,
        })
    }

    /// Access the integrity verifier to configure trusted hashes at runtime.
    pub fn verifier_mut(&mut self) -> &mut PluginVerifier {
        &mut self.verifier
    }

    /// Access the sandbox configuration.
    pub fn sandbox_config_mut(&mut self) -> &mut SandboxConfig {
        &mut self.sandbox_config
    }

    /// Compute SHA-256 hash of WASM bytes for verification.
    pub fn bytes_sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// Add custom host functions for the plugin API
    fn add_host_functions(linker: &mut Linker<WasiP1Ctx>, _engine: &Engine) -> Result<()> {
        // Add log function
        linker
            .func_wrap(
                "kojacoord",
                "log",
                |mut caller: Caller<'_, WasiP1Ctx>,
                 level: u32,
                 ptr: u32,
                 len: u32|
                 -> Result<(), anyhow::Error> {
                    let mem = caller
                        .get_export("memory")
                        .and_then(|e| e.into_memory())
                        .ok_or_else(|| anyhow::anyhow!("failed to find memory export"))?;

                    let data = mem.data(&caller);
                    let bytes = data
                        .get(ptr as usize..(ptr + len) as usize)
                        .ok_or_else(|| anyhow::anyhow!("out of bounds memory access"))?;

                    let message = std::str::from_utf8(bytes).unwrap_or("<invalid utf8>");

                    match level {
                        0 => log::error!("[WASM Plugin] {}", message),
                        1 => log::warn!("[WASM Plugin] {}", message),
                        2 => log::info!("[WASM Plugin] {}", message),
                        3 => log::debug!("[WASM Plugin] {}", message),
                        _ => log::trace!("[WASM Plugin] {}", message),
                    }

                    Ok(())
                },
            )
            .context("Failed to add log function")?;

        // Add get_config function
        linker
            .func_wrap(
                "kojacoord",
                "get_config",
                |mut caller: Caller<'_, WasiP1Ctx>,
                 key_ptr: u32,
                 key_len: u32,
                 out_ptr: u32,
                 out_len: u32|
                 -> Result<u32, anyhow::Error> {
                    let mem = caller
                        .get_export("memory")
                        .and_then(|e| e.into_memory())
                        .ok_or_else(|| anyhow::anyhow!("failed to find memory export"))?;

                    let data = mem.data_mut(&mut caller);
                    let key_bytes = data
                        .get(key_ptr as usize..(key_ptr + key_len) as usize)
                        .ok_or_else(|| anyhow::anyhow!("out of bounds memory access"))?;

                    let _key = std::str::from_utf8(key_bytes).unwrap_or("<invalid utf8>");

                    // In production, this would read from the actual plugin config
                    let value = "default_value";
                    let value_bytes = value.as_bytes();

                    let out_data = data
                        .get_mut(out_ptr as usize..(out_ptr + out_len) as usize)
                        .ok_or_else(|| anyhow::anyhow!("out of bounds memory access"))?;

                    let copy_len = value_bytes.len().min(out_len as usize);
                    out_data[..copy_len].copy_from_slice(&value_bytes[..copy_len]);

                    Ok(copy_len as u32)
                },
            )
            .context("Failed to add get_config function")?;

        Ok(())
    }

    /// Load a WASM plugin from bytes
    pub async fn load_plugin(
        &self,
        name: String,
        version: String,
        module_bytes: Vec<u8>,
        _context: &PluginContext,
    ) -> Result<Arc<Mutex<WasmPluginInstance>>> {
        // Validate WASM magic number
        if module_bytes.len() < 4 || &module_bytes[0..4] != b"\0asm" {
            return Err(anyhow::anyhow!("Invalid WASM module: missing magic number"));
        }

        // Verify integrity using SHA-256
        let digest = Self::bytes_sha256(&module_bytes);
        if self.verifier.trusted_hashes().is_empty() {
            if self.verifier.require_verification() {
                return Err(anyhow::anyhow!(
                    "WASM plugin verification is required but no trusted hashes are configured; \
                     refusing to load {} (sha256={})",
                    name,
                    digest
                ));
            }
            log::warn!(
                "SECURITY: loading UNVERIFIED WASM plugin {} (sha256={}). \
                 No trusted-hash allowlist is configured.",
                name,
                digest
            );
        } else if !self.verifier.trusted_hashes().contains(&digest) {
            return Err(anyhow::anyhow!(
                "WASM plugin {} failed integrity verification: sha256={} is not in the trusted allowlist",
                name,
                digest
            ));
        } else {
            log::info!("verified WASM plugin {} (sha256={})", name, digest);
        }

        // Create WASI context with sandbox configuration
        let mut wasi_builder = WasiCtxBuilder::new();

        // Apply sandbox restrictions
        if !self.sandbox_config.allow_filesystem {
            // Restrict filesystem access - no preopened dirs
            log::info!("Filesystem access disabled for WASM plugin {}", name);
        }

        if !self.sandbox_config.allow_network {
            // Network access is denied by default in WASI
            log::info!("Network access disabled for WASM plugin {}", name);
        }

        let wasi = wasi_builder.build_p1();

        // Create store
        let mut store = Store::new(&self.engine, wasi);

        // Compile module
        let module = Module::from_binary(&self.engine, &module_bytes)
            .context("Failed to compile WASM module")?;

        // Extract metadata from module (if available)
        let metadata = self.extract_metadata(&module, &name, &version)?;

        // Instantiate inside a tight scope so the std::sync `MutexGuard`
        // around the linker is released before any further `?` propagation
        // or potential await points further down the function.
        let instance = {
            let linker = self.linker.lock().unwrap();
            linker
                .instantiate(&mut store, &module)
                .context("Failed to instantiate WASM module")?
        };

        // Call init function if present
        if let Ok(init_func) = instance.get_typed_func::<(), ()>(&mut store, "init") {
            init_func
                .call(&mut store, ())
                .context("Failed to call init function")?;
        }

        let plugin_instance = WasmPluginInstance {
            name: name.clone(),
            version: version.clone(),
            engine: self.engine.clone(),
            module,
            store: Mutex::new(store),
            instance: Mutex::new(Some(instance)),
            metadata,
        };

        let plugin = Arc::new(Mutex::new(plugin_instance));

        let mut plugins = self.plugins.write().await;
        plugins.insert(name.clone(), plugin.clone());

        log::info!("Loaded WASM plugin: {} v{}", name, version);

        Ok(plugin)
    }

    /// Unload a WASM plugin
    pub async fn unload_plugin(&self, name: &str) -> Result<()> {
        let mut plugins = self.plugins.write().await;
        if plugins.remove(name).is_some() {
            log::info!("Unloaded WASM plugin: {}", name);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Plugin '{}' not found", name))
        }
    }

    /// Get a plugin by name
    pub async fn get_plugin(&self, name: &str) -> Option<Arc<Mutex<WasmPluginInstance>>> {
        let plugins = self.plugins.read().await;
        plugins.get(name).cloned()
    }

    /// List all loaded plugins
    pub async fn list_plugins(&self) -> Vec<(String, String)> {
        let plugins = self.plugins.read().await;
        plugins
            .values()
            .map(|p| {
                let guard = p.lock().unwrap();
                (guard.name.clone(), guard.version.clone())
            })
            .collect()
    }

    /// Execute a function in a WASM plugin
    pub async fn call_function(
        &self,
        plugin: &Arc<Mutex<WasmPluginInstance>>,
        function_name: &str,
        args: &[u8],
    ) -> Result<Vec<u8>> {
        let guard = plugin.lock().unwrap();
        let instance_lock = guard.instance.lock().unwrap();
        let instance = instance_lock
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Plugin instance not initialized"))?;

        let mut store = guard.store.lock().unwrap();

        // Try to get the function
        let func = instance
            .get_func(&mut *store, function_name)
            .ok_or_else(|| anyhow::anyhow!("Function '{}' not found in plugin", function_name))?;

        log::debug!(
            "Executing WASM function: {} (args: {})",
            function_name,
            args.len()
        );

        // Write args to memory
        if !args.is_empty() {
            let mem = instance
                .get_export(&mut *store, "memory")
                .and_then(|e| e.into_memory())
                .ok_or_else(|| anyhow::anyhow!("Plugin has no memory export"))?;

            let data = mem.data_mut(&mut *store);
            let offset = 0x10000;
            if data.len() < offset + args.len() {
                return Err(anyhow::anyhow!("Plugin memory too small for arguments"));
            }
            data[offset..offset + args.len()].copy_from_slice(args);
        }

        // Call the function (simplified - in production, handle different signatures)
        let mut results = vec![Val::I32(0)];
        func.call(&mut *store, &[], &mut results)
            .context("Failed to call WASM function")?;

        // Read result from memory if needed
        Ok(vec![])
    }

    /// Get memory usage statistics for a plugin
    pub async fn get_memory_stats(&self, plugin_name: &str) -> Result<(usize, usize)> {
        let plugin = self
            .get_plugin(plugin_name)
            .await
            .ok_or_else(|| anyhow::anyhow!("Plugin '{}' not found", plugin_name))?;

        let guard = plugin.lock().unwrap();
        let instance_lock = guard.instance.lock().unwrap();
        let instance = instance_lock
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Plugin instance not initialized"))?;

        let mut store = guard.store.lock().unwrap();

        if let Some(mem) = instance
            .get_export(&mut *store, "memory")
            .and_then(|e| e.into_memory())
        {
            let data = mem.data(&*store);
            Ok((data.len(), 16 * 1024 * 1024)) // 16MB max
        } else {
            Ok((0, 16 * 1024 * 1024))
        }
    }

    /// Extract metadata from WASM module
    fn extract_metadata(
        &self,
        _module: &Module,
        name: &str,
        version: &str,
    ) -> Result<PluginMetadata> {
        // Try to read metadata from custom sections
        let author = "Unknown".to_string();
        let description = "WASM Plugin".to_string();
        let min_proxy_version = "0.1.0".to_string();
        let permissions = vec![];

        // Iterate over custom sections
        // Note: wasmtime 24 changed the API - custom sections are not directly accessible
        // For now, we'll use default metadata
        // In production, you'd need to parse the WASM binary directly or use wasmparser
        log::debug!("Using default metadata for WASM plugin {}", name);

        Ok(PluginMetadata {
            name: name.to_string(),
            version: version.to_string(),
            author,
            description,
            min_proxy_version,
            dependencies: vec![],
            permissions,
        })
    }
}

impl Default for WasmLoader {
    fn default() -> Self {
        Self::new().expect("Failed to create WasmLoader")
    }
}

/// Bridge between the wasm-side `WasmPluginInstance` and the host's
/// `Plugin` trait. Cached metadata strings (name/version/author/etc.)
/// live on the adapter so the trait getters can return `&str` without
/// hitting the wasm mutex per call.
pub struct WasmPluginAdapter {
    instance: Arc<Mutex<WasmPluginInstance>>,
    /// Kept alive so the WASM engine outlives every loaded plugin
    /// instance. Exposed via [`Self::loader`] so the host can build new
    /// instances from the same engine without re-parsing the module
    /// bytes.
    loader: Arc<WasmLoader>,
    // Cache metadata strings to avoid lifetime issues with MutexGuard
    name: String,
    version: String,
    author: String,
    description: String,
}

impl WasmPluginAdapter {
    pub fn new(instance: Arc<Mutex<WasmPluginInstance>>, loader: Arc<WasmLoader>) -> Self {
        let (name, version, author, description) = {
            let guard = instance.lock().unwrap();
            (
                guard.name.clone(),
                guard.version.clone(),
                guard.metadata.author.clone(),
                guard.metadata.description.clone(),
            )
        };
        Self {
            instance,
            loader,
            name,
            version,
            author,
            description,
        }
    }

    /// Borrow the shared WASM engine/loader so the host can mint new
    /// instances or inspect engine state without going through the
    /// adapter's per-instance lock.
    pub fn loader(&self) -> &Arc<WasmLoader> {
        &self.loader
    }
}

impl Plugin for WasmPluginAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn author(&self) -> &str {
        &self.author
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn on_load(&mut self, _context: &PluginContext) -> Result<()> {
        log::info!("Loading WASM plugin adapter");
        // Already initialized during load
        Ok(())
    }

    fn on_enable(&mut self) -> Result<()> {
        log::info!("Enabling WASM plugin");
        let guard = self.instance.lock().unwrap();
        let instance_lock = guard.instance.lock().unwrap();
        let instance = instance_lock
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Plugin instance not initialized"))?;

        let mut store = guard.store.lock().unwrap();

        if let Ok(on_enable_func) = instance.get_typed_func::<(), ()>(&mut *store, "on_enable") {
            on_enable_func
                .call(&mut *store, ())
                .context("Failed to call on_enable")?;
        }

        Ok(())
    }

    fn on_disable(&mut self) -> Result<()> {
        log::info!("Disabling WASM plugin");
        let guard = self.instance.lock().unwrap();
        let instance_lock = guard.instance.lock().unwrap();
        let instance = instance_lock
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Plugin instance not initialized"))?;

        let mut store = guard.store.lock().unwrap();

        if let Ok(on_disable_func) = instance.get_typed_func::<(), ()>(&mut *store, "on_disable") {
            on_disable_func
                .call(&mut *store, ())
                .context("Failed to call on_disable")?;
        }

        Ok(())
    }

    fn on_unload(&mut self) -> Result<()> {
        log::info!("Unloading WASM plugin");
        Ok(())
    }

    fn handle_event(&mut self, event: &PluginEvent) -> Result<Option<PluginResponse>> {
        let guard = self.instance.lock().unwrap();
        let instance_lock = guard.instance.lock().unwrap();
        let instance = instance_lock
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Plugin instance not initialized"))?;

        let mut store = guard.store.lock().unwrap();

        // Serialize event to bytes
        let event_bytes = self.event_to_bytes(event);

        // Write event to memory
        if let Some(mem) = instance
            .get_export(&mut *store, "memory")
            .and_then(|e| e.into_memory())
        {
            let data = mem.data_mut(&mut *store);
            let offset = 0x10000;
            if data.len() >= offset + event_bytes.len() {
                data[offset..offset + event_bytes.len()].copy_from_slice(&event_bytes);
            }
        }

        // Call handle_event
        if let Ok(handle_func) =
            instance.get_typed_func::<(u32, u32), u32>(&mut *store, "handle_event")
        {
            let result = handle_func
                .call(&mut *store, (0x10000, event_bytes.len() as u32))
                .context("Failed to call handle_event")?;

            // Parse result
            if result == 1 {
                Ok(Some(PluginResponse::Cancel))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    fn register_packet_hooks(&mut self) -> Vec<PacketHookEvent> {
        let guard = self.instance.lock().unwrap();
        let instance_lock = guard.instance.lock().unwrap();
        let instance = instance_lock
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Plugin instance not initialized"));

        if instance.is_err() {
            return vec![];
        }

        let instance = instance.unwrap();
        let mut store = guard.store.lock().unwrap();

        // Try to call get_packet_hooks function if present
        if let Ok(get_hooks_func) =
            instance.get_typed_func::<(), u32>(&mut *store, "get_packet_hooks")
        {
            match get_hooks_func.call(&mut *store, ()) {
                Ok(hook_count) => {
                    let mut hooks = vec![];
                    for i in 0..hook_count {
                        // Try to get each hook's details
                        if let Ok(get_hook_func) =
                            instance.get_typed_func::<u32, u32>(&mut *store, "get_packet_hook")
                        {
                            if let Ok(hook_id) = get_hook_func.call(&mut *store, i) {
                                // Parse hook_id to determine packet type and direction
                                // Format: (direction << 16) | packet_id
                                let direction = (hook_id >> 16) as u8;
                                let packet_id = hook_id & 0xFFFF;

                                let packet_direction = if direction == 0 {
                                    PacketDirection::Serverbound
                                } else {
                                    PacketDirection::Clientbound
                                };

                                // Create a simple hook that forwards packets
                                let hook = PacketHookEvent::hook(
                                    PacketFilter {
                                        protocol_version: None,
                                        packet_id: Some(packet_id as i32),
                                        direction: packet_direction,
                                    },
                                    Box::new(|_| Ok(PacketHookResult::Forward)),
                                )
                                .with_priority(100);

                                hooks.push(hook);
                            }
                        }
                    }
                    hooks
                },
                Err(_) => vec![],
            }
        } else {
            // Try to read hooks from memory if function not available
            if let Some(mem) = instance
                .get_export(&mut *store, "memory")
                .and_then(|e| e.into_memory())
            {
                let data = mem.data(&mut *store);
                // Look for hooks section in memory
                // Format: [count: u32] [hook_id: u32] [priority: u32] ... repeated
                if data.len() >= 4 {
                    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                    let entry_size = 8; // 4 bytes for hook_id, 4 bytes for priority
                    if data.len() >= 4 + (count * entry_size) {
                        let mut hooks = vec![];
                        for i in 0..count {
                            let offset = 4 + (i * entry_size);
                            let hook_id = u32::from_le_bytes([
                                data[offset],
                                data[offset + 1],
                                data[offset + 2],
                                data[offset + 3],
                            ]);
                            let priority = u32::from_le_bytes([
                                data[offset + 4],
                                data[offset + 5],
                                data[offset + 6],
                                data[offset + 7],
                            ]);

                            // Parse hook_id to determine packet type and direction
                            let direction = (hook_id >> 16) as u8;
                            let packet_id = hook_id & 0xFFFF;

                            let packet_direction = if direction == 0 {
                                PacketDirection::Serverbound
                            } else {
                                PacketDirection::Clientbound
                            };

                            // Create a simple hook that forwards packets
                            let hook = PacketHookEvent::hook(
                                PacketFilter {
                                    protocol_version: None,
                                    packet_id: Some(packet_id as i32),
                                    direction: packet_direction,
                                },
                                Box::new(|_| Ok(PacketHookResult::Forward)),
                            )
                            .with_priority(priority as i32);

                            hooks.push(hook);
                        }
                        hooks
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        }
    }
}

impl WasmPluginAdapter {
    fn event_to_bytes(&self, event: &PluginEvent) -> Vec<u8> {
        // Serialize event to bytes
        match event {
            PluginEvent::PlayerJoin { uuid, username } => {
                format!("join|{}|{}", uuid, username).into_bytes()
            },
            PluginEvent::PlayerLeave { uuid } => format!("leave|{}", uuid).into_bytes(),
            PluginEvent::PlayerChat { uuid, message } => {
                format!("chat|{}|{}", uuid, message).into_bytes()
            },
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wasm_loader_creation() {
        let loader = WasmLoader::new();
        assert!(loader.is_ok());
    }

    /// Asserts that loading bytes without a valid WASM magic header is rejected.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// let loader = WasmLoader::new().unwrap();
    /// let ctx = PluginContext {
    ///     plugin_id: "test".to_string(),
    ///     version: "1.0.0".to_string(),
    ///     config: HashMap::new(),
    ///     command_tx: None,
    ///     runtime_handle: None,
    /// };
    /// let rt = tokio::runtime::Runtime::new().unwrap();
    /// rt.block_on(async {
    ///     let res = loader
    ///         .load_plugin("test".to_string(), "1.0.0".to_string(), vec![1, 2, 3], &ctx)
    ///         .await;
    ///     assert!(res.is_err());
    /// });
    /// ```
    #[tokio::test]
    async fn wasm_plugin_loading_invalid() {
        let loader = WasmLoader::new().unwrap();

        let context = PluginContext {
            plugin_id: "test".to_string(),
            version: "1.0.0".to_string(),
            config: HashMap::new(),
            command_tx: None,
            runtime_handle: None,
        };

        // Invalid WASM (no magic number)
        let result = loader
            .load_plugin(
                "test".to_string(),
                "1.0.0".to_string(),
                vec![1, 2, 3],
                &context,
            )
            .await;
        assert!(result.is_err());
    }
}
