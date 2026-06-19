//! Wasmtime-backed plugin loader.
//!
//! Plugins are WebAssembly modules running in a wasmtime sandbox with a
//! whitelist of host imports. Same `Plugin` trait surface as the rest of
//! the host — the [`WasmPluginAdapter`] wraps a `WasmPluginInstance` and
//! forwards every trait method through the wasm function table.
//!
//! # Guest ABI
//!
//! Events and responses cross the boundary as **JSON over linear
//! memory**. A guest module written to this ABI exports:
//!
//! - `alloc(size: u32) -> u32` / `dealloc(ptr: u32, size: u32)` —
//!   guest allocator (recommended; without `alloc` the host uses a fixed
//!   scratch offset that only holds one buffer at a time).
//! - `on_enable()` / `on_disable()` / `init()` — lifecycle (optional).
//! - `handle_event(ptr: u32, len: u32) -> u64` — receives a JSON
//!   [`PluginEvent`] and returns a packed pointer
//!   `((resp_ptr as u64) << 32) | (resp_len as u64)` to a JSON
//!   [`PluginResponse`] in guest memory, or `0` for no response. The
//!   legacy `handle_event(u32, u32) -> u32` (1 = cancel) is also accepted.
//!
//! Host imports (module `"kojacoord"`):
//!
//! - `log(level, ptr, len)`
//! - `get_config(key_ptr, key_len, out_ptr, out_len) -> u32`
//! - `send_command(ptr, len) -> u32` (JSON [`PluginCommand`])
//! - `has_permission(ptr, len) -> u32`
//! - `redis_connect(url_ptr, url_len) -> u32`
//! - `redis_publish(chan_ptr, chan_len, msg_ptr, msg_len) -> u32`
//! - `redis_get(key_ptr, key_len, out_ptr, out_cap) -> i32` (bytes, -1 nil)
//! - `redis_set(key_ptr, key_len, val_ptr, val_len) -> u32`
//! - `redis_del(key_ptr, key_len) -> u32`
//! - `redis_expire(key_ptr, key_len, secs) -> u32`
//! - `redis_subscribe(chan_ptr, chan_len) -> u32` — messages are queued;
//!   pull them with `redis_poll`.
//! - `redis_poll(out_ptr, out_cap) -> i32` — pops one `"channel\npayload"`
//!   message, or -1 when the queue is empty.
//! - `http_request(method_ptr, method_len, url_ptr, url_len, body_ptr,
//!   body_len, out_ptr, out_cap) -> i32` (response bytes, -1 error)

use crate::api::{
    permission_name, PacketDirection, PacketEvent as PacketHookEvent, PacketFilter,
    PacketHookResult, Plugin, PluginContext, PluginEvent, PluginMetadata, PluginPermission,
    PluginResponse,
};
use crate::integrity::PluginVerifier;
use crate::sandbox::SandboxConfig;
use anyhow::{Context, Result};
use futures_util::StreamExt;
use redis::AsyncCommands;
use sha2::digest::Digest;
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::RwLock;
use wasmtime::{Caller, Config, Engine, Instance, Linker, Memory, Module, Store};
use wasmtime_wasi::preview1::WasiP1Ctx;
use wasmtime_wasi::WasiCtxBuilder;

use kojacoord_plugin_abi::PluginCommand;

/// Shared Redis state for a plugin: the connection (cloned per command),
/// the client (for spawning pubsub connections), the inbox of received
/// subscribe messages, and an `alive` flag the subscribe tasks watch so
/// they stop when the plugin is disabled.
#[derive(Clone)]
struct RedisShared {
    client: Arc<Mutex<Option<redis::Client>>>,
    conn: Arc<Mutex<Option<redis::aio::MultiplexedConnection>>>,
    inbox: Arc<Mutex<VecDeque<(String, String)>>>,
    alive: Arc<AtomicBool>,
}

impl RedisShared {
    fn new() -> Self {
        Self {
            client: Arc::new(Mutex::new(None)),
            conn: Arc::new(Mutex::new(None)),
            inbox: Arc::new(Mutex::new(VecDeque::new())),
            alive: Arc::new(AtomicBool::new(true)),
        }
    }

    fn conn(&self) -> Option<redis::aio::MultiplexedConnection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Per-store host state shared with every host import. Carries the WASI
/// context plus the bridge back to the proxy: config, command channel,
/// permissions, the tokio handle (to drive Redis/HTTP), and the HTTP/Redis
/// clients.
pub struct WasmHostState {
    wasi: WasiP1Ctx,
    config: HashMap<String, String>,
    command_tx: Option<UnboundedSender<PluginCommand>>,
    permissions: Vec<PluginPermission>,
    plugin_name: String,
    runtime: Option<tokio::runtime::Handle>,
    redis: RedisShared,
    http: reqwest::Client,
}

impl WasmHostState {
    fn has(&self, perm: PluginPermission) -> bool {
        self.permissions.contains(&perm)
    }
}

/// One loaded plugin's owning state.
pub struct WasmPluginInstance {
    pub name: String,
    pub version: String,
    pub engine: Engine,
    pub module: Module,
    pub store: Mutex<Store<WasmHostState>>,
    pub instance: Mutex<Option<Instance>>,
    pub metadata: PluginMetadata,
}

/// Shared wasmtime engine plus the registry of loaded modules.
pub struct WasmLoader {
    engine: Engine,
    plugins: Arc<RwLock<HashMap<String, Arc<Mutex<WasmPluginInstance>>>>>,
    linker: Mutex<Linker<WasmHostState>>,
    verifier: PluginVerifier,
    sandbox_config: SandboxConfig,
}

/// Drive a future to completion from a synchronous host import. When
/// already inside the runtime (the usual case — `handle_event` runs under
/// the proxy's runtime) we hand off to `block_in_place` so we don't stall
/// the scheduler.
fn run_blocking<F: std::future::Future>(handle: &tokio::runtime::Handle, fut: F) -> F::Output {
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        handle.block_on(fut)
    }
}

impl WasmLoader {
    pub fn new() -> Result<Self> {
        Self::with_config(SandboxConfig::default(), PluginVerifier::new())
    }

    pub fn with_config(sandbox_config: SandboxConfig, verifier: PluginVerifier) -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(false);
        config.wasm_simd(true);
        config.wasm_multi_memory(true);
        config.wasm_threads(false);
        config.wasm_reference_types(true);
        config.max_wasm_stack(512 * 1024);

        let engine = Engine::new(&config).context("Failed to create Wasmtime engine")?;

        let mut linker = Linker::new(&engine);
        wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |s: &mut WasmHostState| {
            &mut s.wasi
        })
        .context("Failed to add WASI to linker")?;

        Self::add_host_functions(&mut linker)?;

        Ok(Self {
            engine,
            plugins: Arc::new(RwLock::new(HashMap::new())),
            linker: Mutex::new(linker),
            verifier,
            sandbox_config,
        })
    }

    pub fn verifier_mut(&mut self) -> &mut PluginVerifier {
        &mut self.verifier
    }

    pub fn sandbox_config_mut(&mut self) -> &mut SandboxConfig {
        &mut self.sandbox_config
    }

    pub fn bytes_sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// Add custom host functions for the plugin API.
    fn add_host_functions(linker: &mut Linker<WasmHostState>) -> Result<()> {
        // kojacoord.log(level, ptr, len)
        linker.func_wrap(
            "kojacoord",
            "log",
            |mut caller: Caller<'_, WasmHostState>, level: u32, ptr: u32, len: u32| {
                let message = read_string(&mut caller, ptr, len)?;
                let name = caller.data().plugin_name.clone();
                match level {
                    0 => log::error!("[wasm:{}] {}", name, message),
                    1 => log::warn!("[wasm:{}] {}", name, message),
                    2 => log::info!("[wasm:{}] {}", name, message),
                    3 => log::debug!("[wasm:{}] {}", name, message),
                    _ => log::trace!("[wasm:{}] {}", name, message),
                }
                Ok::<(), anyhow::Error>(())
            },
        )?;

        // kojacoord.get_config(key_ptr, key_len, out_ptr, out_len) -> bytes_written
        linker.func_wrap(
            "kojacoord",
            "get_config",
            |mut caller: Caller<'_, WasmHostState>,
             key_ptr: u32,
             key_len: u32,
             out_ptr: u32,
             out_len: u32| {
                let key = read_string(&mut caller, key_ptr, key_len)?;
                let value = caller.data().config.get(&key).cloned();
                let Some(value) = value else {
                    return Ok::<u32, anyhow::Error>(0);
                };
                Ok(write_out(&mut caller, out_ptr, out_len, value.as_bytes()))
            },
        )?;

        // kojacoord.send_command(ptr, len) -> 1 ok / 0 fail
        linker.func_wrap(
            "kojacoord",
            "send_command",
            |mut caller: Caller<'_, WasmHostState>, ptr: u32, len: u32| {
                let raw = read_bytes(&mut caller, ptr, len)?;
                let cmd: PluginCommand = match serde_json::from_slice(&raw) {
                    Ok(c) => c,
                    Err(e) => {
                        log::warn!(
                            "[wasm:{}] send_command: bad JSON: {}",
                            caller.data().plugin_name,
                            e
                        );
                        return Ok::<u32, anyhow::Error>(0);
                    },
                };
                Ok(match &caller.data().command_tx {
                    Some(tx) => u32::from(tx.send(cmd).is_ok()),
                    None => 0,
                })
            },
        )?;

        // kojacoord.has_permission(ptr, len) -> 1 granted / 0 denied
        linker.func_wrap(
            "kojacoord",
            "has_permission",
            |mut caller: Caller<'_, WasmHostState>, ptr: u32, len: u32| {
                let name = read_string(&mut caller, ptr, len)?;
                let granted = caller
                    .data()
                    .permissions
                    .iter()
                    .any(|p| permission_name(p).eq_ignore_ascii_case(name.trim()));
                Ok::<u32, anyhow::Error>(u32::from(granted))
            },
        )?;

        Self::add_redis_functions(linker)?;
        Self::add_http_functions(linker)?;
        Ok(())
    }

    fn add_redis_functions(linker: &mut Linker<WasmHostState>) -> Result<()> {
        // redis_connect(url_ptr, url_len) -> 1 ok / 0 fail
        linker.func_wrap(
            "kojacoord",
            "redis_connect",
            |mut caller: Caller<'_, WasmHostState>, ptr: u32, len: u32| {
                let url = read_string(&mut caller, ptr, len)?;
                if !caller.data().has(PluginPermission::UseRedis) {
                    log::warn!(
                        "[wasm:{}] redis_connect denied (no use_redis)",
                        caller.data().plugin_name
                    );
                    return Ok::<u32, anyhow::Error>(0);
                }
                let Some(handle) = caller.data().runtime.clone() else {
                    return Ok(0);
                };
                let redis = caller.data().redis.clone();
                let result = run_blocking(&handle, async move {
                    let client = redis::Client::open(url)?;
                    let conn = client.get_multiplexed_async_connection().await?;
                    Ok::<_, redis::RedisError>((client, conn))
                });
                match result {
                    Ok((client, conn)) => {
                        *redis.client.lock().unwrap() = Some(client);
                        *redis.conn.lock().unwrap() = Some(conn);
                        Ok(1)
                    },
                    Err(e) => {
                        log::warn!(
                            "[wasm:{}] redis_connect failed: {}",
                            caller.data().plugin_name,
                            e
                        );
                        Ok(0)
                    },
                }
            },
        )?;

        // redis_publish(chan_ptr, chan_len, msg_ptr, msg_len) -> 1 ok / 0 fail
        linker.func_wrap(
            "kojacoord",
            "redis_publish",
            |mut caller: Caller<'_, WasmHostState>,
             chan_ptr: u32,
             chan_len: u32,
             msg_ptr: u32,
             msg_len: u32| {
                let chan = read_string(&mut caller, chan_ptr, chan_len)?;
                let msg = read_bytes(&mut caller, msg_ptr, msg_len)?;
                let (Some(handle), Some(mut conn)) = redis_ready(&caller) else {
                    return Ok::<u32, anyhow::Error>(0);
                };
                let ok = run_blocking(
                    &handle,
                    async move { conn.publish::<_, _, ()>(chan, msg).await },
                )
                .is_ok();
                Ok(u32::from(ok))
            },
        )?;

        // redis_get(key_ptr, key_len, out_ptr, out_cap) -> bytes_written / -1 nil
        linker.func_wrap(
            "kojacoord",
            "redis_get",
            |mut caller: Caller<'_, WasmHostState>,
             key_ptr: u32,
             key_len: u32,
             out_ptr: u32,
             out_cap: u32| {
                let key = read_string(&mut caller, key_ptr, key_len)?;
                let (Some(handle), Some(mut conn)) = redis_ready(&caller) else {
                    return Ok::<i32, anyhow::Error>(-1);
                };
                let value: Option<Vec<u8>> =
                    run_blocking(&handle, async move { conn.get(key).await }).unwrap_or(None);
                match value {
                    Some(bytes) => Ok(write_out(&mut caller, out_ptr, out_cap, &bytes) as i32),
                    None => Ok(-1),
                }
            },
        )?;

        // redis_set(key_ptr, key_len, val_ptr, val_len) -> 1 ok / 0 fail
        linker.func_wrap(
            "kojacoord",
            "redis_set",
            |mut caller: Caller<'_, WasmHostState>,
             key_ptr: u32,
             key_len: u32,
             val_ptr: u32,
             val_len: u32| {
                let key = read_string(&mut caller, key_ptr, key_len)?;
                let val = read_bytes(&mut caller, val_ptr, val_len)?;
                let (Some(handle), Some(mut conn)) = redis_ready(&caller) else {
                    return Ok::<u32, anyhow::Error>(0);
                };
                let ok = run_blocking(&handle, async move { conn.set::<_, _, ()>(key, val).await })
                    .is_ok();
                Ok(u32::from(ok))
            },
        )?;

        // redis_del(key_ptr, key_len) -> 1 ok / 0 fail
        linker.func_wrap(
            "kojacoord",
            "redis_del",
            |mut caller: Caller<'_, WasmHostState>, key_ptr: u32, key_len: u32| {
                let key = read_string(&mut caller, key_ptr, key_len)?;
                let (Some(handle), Some(mut conn)) = redis_ready(&caller) else {
                    return Ok::<u32, anyhow::Error>(0);
                };
                let ok = run_blocking(&handle, async move { conn.del::<_, ()>(key).await }).is_ok();
                Ok(u32::from(ok))
            },
        )?;

        // redis_expire(key_ptr, key_len, secs) -> 1 ok / 0 fail
        linker.func_wrap(
            "kojacoord",
            "redis_expire",
            |mut caller: Caller<'_, WasmHostState>, key_ptr: u32, key_len: u32, secs: u32| {
                let key = read_string(&mut caller, key_ptr, key_len)?;
                let (Some(handle), Some(mut conn)) = redis_ready(&caller) else {
                    return Ok::<u32, anyhow::Error>(0);
                };
                let ok = run_blocking(&handle, async move {
                    conn.expire::<_, ()>(key, secs as i64).await
                })
                .is_ok();
                Ok(u32::from(ok))
            },
        )?;

        // redis_subscribe(chan_ptr, chan_len) -> 1 ok / 0 fail
        linker.func_wrap(
            "kojacoord",
            "redis_subscribe",
            |mut caller: Caller<'_, WasmHostState>, chan_ptr: u32, chan_len: u32| {
                let chan = read_string(&mut caller, chan_ptr, chan_len)?;
                if !caller.data().has(PluginPermission::UseRedis) {
                    return Ok::<u32, anyhow::Error>(0);
                }
                let Some(handle) = caller.data().runtime.clone() else {
                    return Ok(0);
                };
                let redis = caller.data().redis.clone();
                let client = redis.client.lock().unwrap().clone();
                let Some(client) = client else {
                    return Ok(0);
                };
                let inbox = redis.inbox.clone();
                let alive = redis.alive.clone();
                handle.spawn(async move {
                    let mut pubsub = match client.get_async_pubsub().await {
                        Ok(p) => p,
                        Err(e) => {
                            log::warn!("wasm redis_subscribe connect failed: {}", e);
                            return;
                        },
                    };
                    if let Err(e) = pubsub.subscribe(&chan).await {
                        log::warn!("wasm redis_subscribe({}) failed: {}", chan, e);
                        return;
                    }
                    let mut stream = pubsub.on_message();
                    while alive.load(Ordering::Relaxed) {
                        match stream.next().await {
                            Some(msg) => {
                                let channel = msg.get_channel_name().to_string();
                                if let Ok(payload) = msg.get_payload::<String>() {
                                    let mut q = inbox.lock().unwrap_or_else(|e| e.into_inner());
                                    // Bound the queue so a guest that stops
                                    // polling can't grow it without limit.
                                    if q.len() < 4096 {
                                        q.push_back((channel, payload));
                                    }
                                }
                            },
                            None => break,
                        }
                    }
                });
                Ok(1)
            },
        )?;

        // redis_psubscribe(pattern_ptr, pattern_len) -> 1 ok / 0 fail.
        // Pattern subscribe; messages land in the same inbox as subscribe,
        // tagged with their concrete channel.
        linker.func_wrap(
            "kojacoord",
            "redis_psubscribe",
            |mut caller: Caller<'_, WasmHostState>, pat_ptr: u32, pat_len: u32| {
                let pattern = read_string(&mut caller, pat_ptr, pat_len)?;
                if !caller.data().has(PluginPermission::UseRedis) {
                    return Ok::<u32, anyhow::Error>(0);
                }
                let Some(handle) = caller.data().runtime.clone() else {
                    return Ok(0);
                };
                let redis = caller.data().redis.clone();
                let client = redis.client.lock().unwrap().clone();
                let Some(client) = client else {
                    return Ok(0);
                };
                let inbox = redis.inbox.clone();
                let alive = redis.alive.clone();
                handle.spawn(async move {
                    let mut pubsub = match client.get_async_pubsub().await {
                        Ok(p) => p,
                        Err(e) => {
                            log::warn!("wasm redis_psubscribe connect failed: {}", e);
                            return;
                        },
                    };
                    if let Err(e) = pubsub.psubscribe(&pattern).await {
                        log::warn!("wasm redis_psubscribe({}) failed: {}", pattern, e);
                        return;
                    }
                    let mut stream = pubsub.on_message();
                    while alive.load(Ordering::Relaxed) {
                        match stream.next().await {
                            Some(msg) => {
                                let channel = msg.get_channel_name().to_string();
                                if let Ok(payload) = msg.get_payload::<String>() {
                                    let mut q = inbox.lock().unwrap_or_else(|e| e.into_inner());
                                    if q.len() < 4096 {
                                        q.push_back((channel, payload));
                                    }
                                }
                            },
                            None => break,
                        }
                    }
                });
                Ok(1)
            },
        )?;

        // redis_poll(out_ptr, out_cap) -> bytes_written / -1 empty
        linker.func_wrap(
            "kojacoord",
            "redis_poll",
            |mut caller: Caller<'_, WasmHostState>, out_ptr: u32, out_cap: u32| {
                let item = caller
                    .data()
                    .redis
                    .inbox
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .pop_front();
                match item {
                    Some((chan, payload)) => {
                        let combined = format!("{}\n{}", chan, payload);
                        Ok::<i32, anyhow::Error>(write_out(
                            &mut caller,
                            out_ptr,
                            out_cap,
                            combined.as_bytes(),
                        ) as i32)
                    },
                    None => Ok(-1),
                }
            },
        )?;

        Ok(())
    }

    fn add_http_functions(linker: &mut Linker<WasmHostState>) -> Result<()> {
        // http_request(method, url, body, out) -> response_bytes / -1 error
        linker.func_wrap(
            "kojacoord",
            "http_request",
            |mut caller: Caller<'_, WasmHostState>,
             method_ptr: u32,
             method_len: u32,
             url_ptr: u32,
             url_len: u32,
             body_ptr: u32,
             body_len: u32,
             out_ptr: u32,
             out_cap: u32| {
                let method = read_string(&mut caller, method_ptr, method_len)?;
                let url = read_string(&mut caller, url_ptr, url_len)?;
                let body = read_bytes(&mut caller, body_ptr, body_len)?;
                if !caller.data().has(PluginPermission::UseHttp) {
                    log::warn!(
                        "[wasm:{}] http_request denied (no use_http)",
                        caller.data().plugin_name
                    );
                    return Ok::<i32, anyhow::Error>(-1);
                }
                let Some(handle) = caller.data().runtime.clone() else {
                    return Ok(-1);
                };
                let client = caller.data().http.clone();
                let result = run_blocking(&handle, async move {
                    let m = reqwest::Method::from_bytes(method.as_bytes())
                        .unwrap_or(reqwest::Method::GET);
                    let mut req = client.request(m, &url);
                    if !body.is_empty() {
                        req = req.body(body);
                    }
                    let resp = req.send().await?;
                    let bytes = resp.bytes().await?;
                    Ok::<Vec<u8>, reqwest::Error>(bytes.to_vec())
                });
                match result {
                    Ok(bytes) => Ok(write_out(&mut caller, out_ptr, out_cap, &bytes) as i32),
                    Err(e) => {
                        log::warn!(
                            "[wasm:{}] http_request failed: {}",
                            caller.data().plugin_name,
                            e
                        );
                        Ok(-1)
                    },
                }
            },
        )?;
        Ok(())
    }

    /// Load a WASM plugin from bytes.
    pub async fn load_plugin(
        &self,
        name: String,
        version: String,
        module_bytes: Vec<u8>,
        context: &PluginContext,
    ) -> Result<Arc<Mutex<WasmPluginInstance>>> {
        if module_bytes.len() < 8 || &module_bytes[0..4] != b"\0asm" {
            return Err(anyhow::anyhow!("Invalid WASM module: missing magic number"));
        }

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

        // Provisional metadata from the custom section (used as a fallback
        // for guests that don't export a runtime `metadata()` function). The
        // permissions are finalised after instantiation below.
        let mut metadata = Self::extract_metadata(&module_bytes, &name, &version);

        let mut wasi_builder = WasiCtxBuilder::new();
        if !self.sandbox_config.allow_filesystem {
            log::info!("Filesystem access disabled for WASM plugin {}", name);
        }
        if !self.sandbox_config.allow_network {
            log::info!("Network access disabled for WASM plugin {}", name);
        }
        let wasi = wasi_builder.build_p1();

        let host_state = WasmHostState {
            wasi,
            config: context.config.clone(),
            command_tx: context.command_tx.clone(),
            permissions: metadata.permissions.clone(),
            plugin_name: name.clone(),
            runtime: context
                .runtime_handle
                .clone()
                .or_else(|| tokio::runtime::Handle::try_current().ok()),
            redis: RedisShared::new(),
            http: reqwest::Client::new(),
        };

        let mut store = Store::new(&self.engine, host_state);

        let module = Module::from_binary(&self.engine, &module_bytes)
            .context("Failed to compile WASM module")?;

        let instance = {
            let linker = self.linker.lock().unwrap();
            linker
                .instantiate(&mut store, &module)
                .context("Failed to instantiate WASM module")?
        };

        if let Ok(init_func) = instance.get_typed_func::<(), ()>(&mut store, "init") {
            init_func
                .call(&mut store, ())
                .context("Failed to call init function")?;
        }

        // Prefer a typed runtime manifest (the guest's `metadata()` export,
        // generated by the SDK's `plugin_manifest!`). It overrides the
        // section fallback and, importantly, sets the granted permissions
        // the network host imports gate on.
        if let Some(rt_meta) = Self::read_runtime_metadata(&mut store, &instance) {
            metadata = rt_meta;
            store.data_mut().permissions = metadata.permissions.clone();
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
        self.plugins
            .write()
            .await
            .insert(name.clone(), plugin.clone());
        log::info!("Loaded WASM plugin: {} v{}", name, version);
        Ok(plugin)
    }

    pub async fn unload_plugin(&self, name: &str) -> Result<()> {
        let mut plugins = self.plugins.write().await;
        if plugins.remove(name).is_some() {
            log::info!("Unloaded WASM plugin: {}", name);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Plugin '{}' not found", name))
        }
    }

    pub async fn get_plugin(&self, name: &str) -> Option<Arc<Mutex<WasmPluginInstance>>> {
        self.plugins.read().await.get(name).cloned()
    }

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
            Ok((data.len(), 16 * 1024 * 1024))
        } else {
            Ok((0, 16 * 1024 * 1024))
        }
    }

    /// Call the guest's optional `metadata() -> u64` export (emitted by the
    /// SDK's `plugin_manifest!`) and parse the JSON [`PluginMetadata`] it
    /// points at. Returns `None` if the guest doesn't export it or the call
    /// fails — the caller then falls back to the custom-section metadata.
    fn read_runtime_metadata(
        store: &mut Store<WasmHostState>,
        instance: &Instance,
    ) -> Option<PluginMetadata> {
        let func = instance
            .get_typed_func::<(), u64>(&mut *store, "metadata")
            .ok()?;
        let packed = func.call(&mut *store, ()).ok()?;
        if packed == 0 {
            return None;
        }
        let ptr = (packed >> 32) as u32;
        let len = (packed & 0xFFFF_FFFF) as u32;
        let bytes = read_guest_bytes(*instance, store, ptr, len)?;
        free_in_guest(*instance, store, ptr, len);
        match serde_json::from_slice::<PluginMetadata>(&bytes) {
            Ok(m) => Some(m),
            Err(e) => {
                log::warn!("WASM plugin metadata() returned unparsable JSON: {}", e);
                None
            },
        }
    }

    /// Extract metadata from a `kojacoord_metadata` / `kojacoord:meta`
    /// custom section (JSON [`PluginMetadata`]). Falls back to defaults.
    fn extract_metadata(module_bytes: &[u8], name: &str, version: &str) -> PluginMetadata {
        let fallback = || PluginMetadata {
            name: name.to_string(),
            version: version.to_string(),
            author: "Unknown".to_string(),
            description: "WASM Plugin".to_string(),
            min_proxy_version: "0.1.0".to_string(),
            dependencies: vec![],
            permissions: vec![],
        };

        match find_custom_section(module_bytes, &["kojacoord_metadata", "kojacoord:meta"]) {
            Some(payload) => match serde_json::from_slice::<PluginMetadata>(payload) {
                Ok(mut meta) => {
                    if meta.name.is_empty() {
                        meta.name = name.to_string();
                    }
                    if meta.version.is_empty() {
                        meta.version = version.to_string();
                    }
                    log::info!("Parsed embedded metadata for WASM plugin {}", name);
                    meta
                },
                Err(e) => {
                    log::warn!(
                        "WASM plugin {} has a metadata section but it didn't parse ({}); using defaults",
                        name,
                        e
                    );
                    fallback()
                },
            },
            None => fallback(),
        }
    }
}

impl Default for WasmLoader {
    fn default() -> Self {
        Self::new().expect("Failed to create WasmLoader")
    }
}

/// Both the runtime handle and a live Redis connection, or `(None, None)`
/// if either is missing or the plugin lacks `use_redis`.
fn redis_ready(
    caller: &Caller<'_, WasmHostState>,
) -> (
    Option<tokio::runtime::Handle>,
    Option<redis::aio::MultiplexedConnection>,
) {
    let data = caller.data();
    if !data.has(PluginPermission::UseRedis) {
        return (None, None);
    }
    (data.runtime.clone(), data.redis.conn())
}

/// Fetch the guest's exported `memory`.
fn memory(caller: &mut Caller<'_, WasmHostState>) -> Result<Memory> {
    caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| anyhow::anyhow!("plugin has no exported memory"))
}

/// Read `len` bytes at `ptr` out of guest memory.
fn read_bytes(caller: &mut Caller<'_, WasmHostState>, ptr: u32, len: u32) -> Result<Vec<u8>> {
    let mem = memory(caller)?;
    let mut buf = vec![0u8; len as usize];
    mem.read(&*caller, ptr as usize, &mut buf)
        .map_err(|e| anyhow::anyhow!("out of bounds memory read: {e}"))?;
    Ok(buf)
}

/// Read a UTF-8 string at `[ptr, len)` out of guest memory (lossy).
fn read_string(caller: &mut Caller<'_, WasmHostState>, ptr: u32, len: u32) -> Result<String> {
    Ok(String::from_utf8_lossy(&read_bytes(caller, ptr, len)?).into_owned())
}

/// Write up to `cap` bytes of `data` into guest memory at `ptr`; returns
/// the number of bytes written (0 on any error).
fn write_out(caller: &mut Caller<'_, WasmHostState>, ptr: u32, cap: u32, data: &[u8]) -> u32 {
    let Ok(mem) = memory(caller) else {
        return 0;
    };
    let n = data.len().min(cap as usize);
    if mem.write(&mut *caller, ptr as usize, &data[..n]).is_err() {
        return 0;
    }
    n as u32
}

/// Walk a WASM binary and return the payload of the first custom section
/// whose name matches one of `names`. Dependency-free.
fn find_custom_section<'a>(bytes: &'a [u8], names: &[&str]) -> Option<&'a [u8]> {
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        return None;
    }
    let mut pos = 8usize;
    while pos < bytes.len() {
        let id = bytes[pos];
        pos += 1;
        let (size, used) = read_varu32(&bytes[pos..])?;
        pos += used;
        let body_end = pos.checked_add(size as usize)?;
        if body_end > bytes.len() {
            return None;
        }
        if id == 0 {
            let section = &bytes[pos..body_end];
            if let Some((name_len, name_used)) = read_varu32(section) {
                let name_start = name_used;
                let name_end = name_start.checked_add(name_len as usize)?;
                if name_end <= section.len() {
                    let sec_name = &section[name_start..name_end];
                    if names.iter().any(|n| n.as_bytes() == sec_name) {
                        return Some(&section[name_end..]);
                    }
                }
            }
        }
        pos = body_end;
    }
    None
}

/// Decode an unsigned LEB128 `u32`, returning `(value, bytes_consumed)`.
fn read_varu32(bytes: &[u8]) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0;
    for (i, &b) in bytes.iter().enumerate().take(5) {
        result |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

/// Bridge between the wasm-side `WasmPluginInstance` and the host's
/// `Plugin` trait.
pub struct WasmPluginAdapter {
    instance: Arc<Mutex<WasmPluginInstance>>,
    loader: Arc<WasmLoader>,
    name: String,
    version: String,
    author: String,
    description: String,
    subscribed_events: u32,
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
            subscribed_events: kojacoord_plugin_abi::ALL_EVENTS,
        }
    }

    pub fn loader(&self) -> &Arc<WasmLoader> {
        &self.loader
    }

    /// Call a no-arg lifecycle export if the guest provides it.
    fn call_lifecycle(&self, func_name: &str) -> Result<()> {
        let guard = self.instance.lock().unwrap();
        let instance_lock = guard.instance.lock().unwrap();
        let instance = instance_lock
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Plugin instance not initialized"))?;
        let mut store = guard.store.lock().unwrap();
        if let Ok(func) = instance.get_typed_func::<(), ()>(&mut *store, func_name) {
            func.call(&mut *store, ())
                .with_context(|| format!("Failed to call {func_name}"))?;
        }
        Ok(())
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

    fn subscribed_events(&self) -> u32 {
        self.subscribed_events
    }

    fn on_load(&mut self, _context: &PluginContext) -> Result<()> {
        log::info!("Loading WASM plugin adapter: {}", self.name);
        Ok(())
    }

    fn on_enable(&mut self) -> Result<()> {
        self.call_lifecycle("on_enable")
    }

    fn on_disable(&mut self) -> Result<()> {
        // Stop any Redis subscribe tasks belonging to this plugin.
        {
            let guard = self.instance.lock().unwrap();
            let store = guard.store.lock().unwrap();
            store.data().redis.alive.store(false, Ordering::Relaxed);
        }
        self.call_lifecycle("on_disable")
    }

    fn on_unload(&mut self) -> Result<()> {
        log::info!("Unloading WASM plugin: {}", self.name);
        Ok(())
    }

    fn handle_event(&mut self, event: &PluginEvent) -> Result<Option<PluginResponse>> {
        let guard = self.instance.lock().unwrap();
        let instance_lock = guard.instance.lock().unwrap();
        let instance = match instance_lock.as_ref() {
            Some(i) => *i,
            None => return Ok(None),
        };
        let mut store = guard.store.lock().unwrap();

        let event_bytes = match serde_json::to_vec(event) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("[wasm:{}] event serialization failed: {}", self.name, e);
                return Ok(None);
            },
        };

        let (in_ptr, in_len) = match write_to_guest(instance, &mut store, &event_bytes) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("[wasm:{}] could not pass event to guest: {}", self.name, e);
                return Ok(None);
            },
        };

        // Preferred ABI: handle_event(ptr, len) -> u64 packed response.
        if let Ok(func) = instance.get_typed_func::<(u32, u32), u64>(&mut *store, "handle_event") {
            let packed = func
                .call(&mut *store, (in_ptr, in_len))
                .context("handle_event call failed")?;
            free_in_guest(instance, &mut store, in_ptr, in_len);
            if packed == 0 {
                return Ok(None);
            }
            let resp_ptr = (packed >> 32) as u32;
            let resp_len = (packed & 0xFFFF_FFFF) as u32;
            let resp = read_guest_bytes(instance, &mut store, resp_ptr, resp_len);
            free_in_guest(instance, &mut store, resp_ptr, resp_len);
            return Ok(match resp {
                Some(bytes) => serde_json::from_slice::<PluginResponse>(&bytes).ok(),
                None => None,
            });
        }

        // Legacy ABI: handle_event(ptr, len) -> u32 (1 = cancel).
        if let Ok(func) = instance.get_typed_func::<(u32, u32), u32>(&mut *store, "handle_event") {
            let result = func
                .call(&mut *store, (in_ptr, in_len))
                .context("handle_event (legacy) call failed")?;
            free_in_guest(instance, &mut store, in_ptr, in_len);
            return Ok(if result == 1 {
                Some(PluginResponse::Cancel)
            } else {
                None
            });
        }

        free_in_guest(instance, &mut store, in_ptr, in_len);
        Ok(None)
    }

    fn drain_redis_messages(&mut self) -> Vec<(String, String)> {
        let guard = self.instance.lock().unwrap();
        let store = guard.store.lock().unwrap();
        let mut q = store
            .data()
            .redis
            .inbox
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        q.drain(..).collect()
    }

    fn register_packet_hooks(&mut self) -> Vec<PacketHookEvent> {
        let guard = self.instance.lock().unwrap();
        let instance_lock = guard.instance.lock().unwrap();
        let instance = match instance_lock.as_ref() {
            Some(i) => *i,
            None => return vec![],
        };
        let mut store = guard.store.lock().unwrap();

        let Ok(get_hooks) = instance.get_typed_func::<(), u32>(&mut *store, "get_packet_hooks")
        else {
            return vec![];
        };
        let Ok(count) = get_hooks.call(&mut *store, ()) else {
            return vec![];
        };
        let Ok(get_hook) = instance.get_typed_func::<u32, u32>(&mut *store, "get_packet_hook")
        else {
            return vec![];
        };

        let mut hooks = Vec::new();
        for i in 0..count.min(1024) {
            let Ok(hook_id) = get_hook.call(&mut *store, i) else {
                continue;
            };
            let direction = if (hook_id >> 16) == 0 {
                PacketDirection::Serverbound
            } else {
                PacketDirection::Clientbound
            };
            let packet_id = (hook_id & 0xFFFF) as i32;
            hooks.push(
                PacketHookEvent::hook(
                    PacketFilter {
                        protocol_version: None,
                        packet_id: Some(packet_id),
                        direction,
                    },
                    Box::new(|_| Ok(PacketHookResult::Forward)),
                )
                .with_priority(100),
            );
        }
        hooks
    }
}

/// Write `bytes` into guest memory (via `alloc` when available).
fn write_to_guest(
    instance: Instance,
    store: &mut Store<WasmHostState>,
    bytes: &[u8],
) -> Result<(u32, u32)> {
    let mem = instance
        .get_export(&mut *store, "memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| anyhow::anyhow!("plugin has no exported memory"))?;

    if let Ok(alloc) = instance.get_typed_func::<u32, u32>(&mut *store, "alloc") {
        let ptr = alloc
            .call(&mut *store, bytes.len() as u32)
            .context("guest alloc failed")?;
        mem.write(&mut *store, ptr as usize, bytes)
            .context("write to alloc'd guest memory failed")?;
        Ok((ptr, bytes.len() as u32))
    } else {
        let offset = 0x10000usize;
        let data = mem.data_mut(&mut *store);
        if data.len() < offset + bytes.len() {
            return Err(anyhow::anyhow!("guest memory too small for event"));
        }
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok((offset as u32, bytes.len() as u32))
    }
}

/// Read `len` bytes at `ptr` from guest memory, or `None` on any error.
fn read_guest_bytes(
    instance: Instance,
    store: &mut Store<WasmHostState>,
    ptr: u32,
    len: u32,
) -> Option<Vec<u8>> {
    let mem = instance
        .get_export(&mut *store, "memory")
        .and_then(|e| e.into_memory())?;
    let mut buf = vec![0u8; len as usize];
    mem.read(&*store, ptr as usize, &mut buf).ok()?;
    Some(buf)
}

/// Free a guest buffer via the optional `dealloc` export.
fn free_in_guest(instance: Instance, store: &mut Store<WasmHostState>, ptr: u32, len: u32) {
    if ptr == 0x10000 {
        return;
    }
    if let Ok(dealloc) = instance.get_typed_func::<(u32, u32), ()>(&mut *store, "dealloc") {
        let _ = dealloc.call(&mut *store, (ptr, len));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wasm_loader_creation() {
        assert!(WasmLoader::new().is_ok());
    }

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

    #[test]
    fn varu32_decodes_multibyte() {
        assert_eq!(read_varu32(&[0xAC, 0x02]), Some((300, 2)));
        assert_eq!(read_varu32(&[0x00]), Some((0, 1)));
    }

    #[test]
    fn custom_section_missing_is_none() {
        let bytes = b"\0asm\x01\0\0\0";
        assert!(find_custom_section(bytes, &["kojacoord_metadata"]).is_none());
    }
}
