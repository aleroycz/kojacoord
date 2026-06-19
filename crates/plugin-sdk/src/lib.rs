//! Guest SDK for Kojacoord WASM plugins.
//!
//! Plugin authors add this crate plus [`kojacoord-plugin-abi`], implement
//! the [`Plugin`] trait, and call [`export_plugin!`] once. The macro emits
//! the C ABI exports the host expects (`alloc`/`dealloc`/`handle_event`/
//! `init`/`on_enable`/`on_disable`) and wires JSON (de)serialization, so
//! authors never touch raw pointers or marshal JSON by hand.
//!
//! Host services are exposed as ordinary functions: [`log`], [`get_config`],
//! [`send_command`], [`has_permission`], the `redis_*` family, and
//! [`http_request`]. On non-wasm targets these are inert stubs so the crate
//! still builds in a normal workspace `cargo check`.
//!
//! ```ignore
//! use kojacoord_plugin_sdk::*;
//!
//! struct MyPlugin;
//! impl Plugin for MyPlugin {
//!     fn on_enable(&mut self) {
//!         log(LogLevel::Info, "hello from wasm");
//!         redis_connect(&get_config("redis_url").unwrap_or_default());
//!         redis_subscribe("kojacoord:sanctions");
//!     }
//!     fn handle_event(&mut self, ev: &PluginEvent) -> Option<PluginResponse> {
//!         if let PluginEvent::RedisMessage { channel, payload } = ev {
//!             log(LogLevel::Info, &format!("{channel}: {payload}"));
//!         }
//!         None
//!     }
//! }
//! export_plugin!(MyPlugin, MyPlugin);
//! ```

pub use kojacoord_plugin_abi::{
    permission_name, CommandSender, PlayerSample, PluginCommand, PluginCommandSpec, PluginEvent,
    PluginEventKind, PluginMetadata, PluginPermission, PluginResponse, ALL_EVENTS,
};
pub use uuid::Uuid;

/// Log levels accepted by the host `log` import.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

/// The trait a WASM plugin implements. Every method has a default, so a
/// plugin overrides only what it needs.
pub trait Plugin {
    /// Called once when the plugin is enabled. Set up Redis/HTTP here.
    fn on_enable(&mut self) {}
    /// Called when the plugin is disabled.
    fn on_disable(&mut self) {}
    /// Handle a proxy event. Return a [`PluginResponse`] to act on it
    /// (e.g. [`PluginResponse::Cancel`]) or `None` to pass.
    fn handle_event(&mut self, _event: &PluginEvent) -> Option<PluginResponse> {
        None
    }
}

// ---------------------------------------------------------------------------
// Host imports (module "kojacoord"). On wasm32 these bind to the proxy host;
// elsewhere they are stubs so the crate compiles in the workspace.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "kojacoord")]
extern "C" {
    #[link_name = "log"]
    fn ext_log(level: u32, ptr: u32, len: u32);
    #[link_name = "get_config"]
    fn ext_get_config(key_ptr: u32, key_len: u32, out_ptr: u32, out_len: u32) -> u32;
    #[link_name = "send_command"]
    fn ext_send_command(ptr: u32, len: u32) -> u32;
    #[link_name = "has_permission"]
    fn ext_has_permission(ptr: u32, len: u32) -> u32;
    #[link_name = "redis_connect"]
    fn ext_redis_connect(ptr: u32, len: u32) -> u32;
    #[link_name = "redis_publish"]
    fn ext_redis_publish(c_ptr: u32, c_len: u32, m_ptr: u32, m_len: u32) -> u32;
    #[link_name = "redis_get"]
    fn ext_redis_get(k_ptr: u32, k_len: u32, out_ptr: u32, out_cap: u32) -> i32;
    #[link_name = "redis_set"]
    fn ext_redis_set(k_ptr: u32, k_len: u32, v_ptr: u32, v_len: u32) -> u32;
    #[link_name = "redis_del"]
    fn ext_redis_del(k_ptr: u32, k_len: u32) -> u32;
    #[link_name = "redis_expire"]
    fn ext_redis_expire(k_ptr: u32, k_len: u32, secs: u32) -> u32;
    #[link_name = "redis_subscribe"]
    fn ext_redis_subscribe(c_ptr: u32, c_len: u32) -> u32;
    #[link_name = "redis_psubscribe"]
    fn ext_redis_psubscribe(p_ptr: u32, p_len: u32) -> u32;
    #[link_name = "redis_poll"]
    fn ext_redis_poll(out_ptr: u32, out_cap: u32) -> i32;
    #[link_name = "http_request"]
    #[allow(clippy::too_many_arguments)]
    fn ext_http_request(
        m_ptr: u32,
        m_len: u32,
        u_ptr: u32,
        u_len: u32,
        b_ptr: u32,
        b_len: u32,
        out_ptr: u32,
        out_cap: u32,
    ) -> i32;
}

// Non-wasm stubs.
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::too_many_arguments, unused_variables)]
mod stubs {
    pub unsafe fn ext_log(_: u32, _: u32, _: u32) {}
    pub unsafe fn ext_get_config(_: u32, _: u32, _: u32, _: u32) -> u32 {
        0
    }
    pub unsafe fn ext_send_command(_: u32, _: u32) -> u32 {
        0
    }
    pub unsafe fn ext_has_permission(_: u32, _: u32) -> u32 {
        0
    }
    pub unsafe fn ext_redis_connect(_: u32, _: u32) -> u32 {
        0
    }
    pub unsafe fn ext_redis_publish(_: u32, _: u32, _: u32, _: u32) -> u32 {
        0
    }
    pub unsafe fn ext_redis_get(_: u32, _: u32, _: u32, _: u32) -> i32 {
        -1
    }
    pub unsafe fn ext_redis_set(_: u32, _: u32, _: u32, _: u32) -> u32 {
        0
    }
    pub unsafe fn ext_redis_del(_: u32, _: u32) -> u32 {
        0
    }
    pub unsafe fn ext_redis_expire(_: u32, _: u32, _: u32) -> u32 {
        0
    }
    pub unsafe fn ext_redis_subscribe(_: u32, _: u32) -> u32 {
        0
    }
    pub unsafe fn ext_redis_psubscribe(_: u32, _: u32) -> u32 {
        0
    }
    pub unsafe fn ext_redis_poll(_: u32, _: u32) -> i32 {
        -1
    }
    pub unsafe fn ext_http_request(
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
    ) -> i32 {
        -1
    }
}
#[cfg(not(target_arch = "wasm32"))]
use stubs::*;

#[inline]
fn p(s: &[u8]) -> u32 {
    s.as_ptr() as usize as u32
}

/// Emit a log line to the proxy.
pub fn log(level: LogLevel, message: &str) {
    unsafe { ext_log(level as u32, p(message.as_bytes()), message.len() as u32) }
}

/// Read a plugin config value by key.
pub fn get_config(key: &str) -> Option<String> {
    let mut buf = vec![0u8; 8192];
    let n = unsafe {
        ext_get_config(
            p(key.as_bytes()),
            key.len() as u32,
            p(&buf),
            buf.len() as u32,
        )
    };
    if n == 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// Send a privileged command to the proxy.
pub fn send_command(cmd: &PluginCommand) -> bool {
    let json = match serde_json::to_vec(cmd) {
        Ok(j) => j,
        Err(_) => return false,
    };
    unsafe { ext_send_command(p(&json), json.len() as u32) == 1 }
}

/// True if the plugin's manifest was granted `permission` (snake_case name).
pub fn has_permission(permission: &str) -> bool {
    unsafe { ext_has_permission(p(permission.as_bytes()), permission.len() as u32) == 1 }
}

/// Open the plugin's Redis connection (call once, before publish/get/etc.).
pub fn redis_connect(url: &str) -> bool {
    unsafe { ext_redis_connect(p(url.as_bytes()), url.len() as u32) == 1 }
}

/// Publish a message to a Redis channel.
pub fn redis_publish(channel: &str, message: &str) -> bool {
    unsafe {
        ext_redis_publish(
            p(channel.as_bytes()),
            channel.len() as u32,
            p(message.as_bytes()),
            message.len() as u32,
        ) == 1
    }
}

/// GET a key. `None` when the key is missing.
pub fn redis_get(key: &str) -> Option<String> {
    let mut buf = vec![0u8; 65536];
    let n = unsafe {
        ext_redis_get(
            p(key.as_bytes()),
            key.len() as u32,
            p(&buf),
            buf.len() as u32,
        )
    };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

/// SET a key.
pub fn redis_set(key: &str, value: &str) -> bool {
    unsafe {
        ext_redis_set(
            p(key.as_bytes()),
            key.len() as u32,
            p(value.as_bytes()),
            value.len() as u32,
        ) == 1
    }
}

/// DEL a key.
pub fn redis_del(key: &str) -> bool {
    unsafe { ext_redis_del(p(key.as_bytes()), key.len() as u32) == 1 }
}

/// EXPIRE a key after `secs` seconds.
pub fn redis_expire(key: &str, secs: u32) -> bool {
    unsafe { ext_redis_expire(p(key.as_bytes()), key.len() as u32, secs) == 1 }
}

/// Subscribe to a Redis channel. Messages arrive as
/// [`PluginEvent::RedisMessage`] (if subscribed) and/or via [`redis_poll`].
pub fn redis_subscribe(channel: &str) -> bool {
    unsafe { ext_redis_subscribe(p(channel.as_bytes()), channel.len() as u32) == 1 }
}

/// Pattern-subscribe to Redis channels (e.g. `join.*`). Messages arrive
/// the same way as [`redis_subscribe`], tagged with their real channel.
pub fn redis_psubscribe(pattern: &str) -> bool {
    unsafe { ext_redis_psubscribe(p(pattern.as_bytes()), pattern.len() as u32) == 1 }
}

/// Pull the next pending subscribe message as `(channel, payload)`, or
/// `None` if the queue is empty.
pub fn redis_poll() -> Option<(String, String)> {
    let mut buf = vec![0u8; 65536];
    let n = unsafe { ext_redis_poll(p(&buf), buf.len() as u32) };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    let s = String::from_utf8(buf).ok()?;
    let (chan, payload) = s.split_once('\n')?;
    Some((chan.to_string(), payload.to_string()))
}

/// Make an outbound HTTP request; returns the response body bytes.
pub fn http_request(method: &str, url: &str, body: &[u8]) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 1 << 20];
    let n = unsafe {
        ext_http_request(
            p(method.as_bytes()),
            method.len() as u32,
            p(url.as_bytes()),
            url.len() as u32,
            p(body),
            body.len() as u32,
            p(&buf),
            buf.len() as u32,
        )
    };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

/// Convenience: HTTP GET returning the body as a UTF-8 string.
pub fn http_get(url: &str) -> Option<String> {
    http_request("GET", url, &[]).and_then(|b| String::from_utf8(b).ok())
}

// ---------------------------------------------------------------------------
// ABI plumbing used by `export_plugin!`. Public because the macro expands in
// the plugin crate, but not meant to be called directly.
// ---------------------------------------------------------------------------

/// Allocate `size` bytes the host can write into. Matches the host's
/// `dealloc(ptr, size)` layout (align 1).
#[doc(hidden)]
pub fn __alloc(size: u32) -> u32 {
    if size == 0 {
        return 0;
    }
    let layout = std::alloc::Layout::from_size_align(size as usize, 1).expect("layout");
    unsafe { std::alloc::alloc(layout) as usize as u32 }
}

#[doc(hidden)]
pub fn __dealloc(ptr: u32, size: u32) {
    if ptr == 0 || size == 0 {
        return;
    }
    let layout = std::alloc::Layout::from_size_align(size as usize, 1).expect("layout");
    unsafe { std::alloc::dealloc(ptr as usize as *mut u8, layout) }
}

/// Decode a JSON event the host wrote at `[ptr, len)`.
#[doc(hidden)]
pub fn __decode_event(ptr: u32, len: u32) -> Option<PluginEvent> {
    let bytes = unsafe { std::slice::from_raw_parts(ptr as usize as *const u8, len as usize) };
    serde_json::from_slice(bytes).ok()
}

/// Serialize a response into a freshly allocated guest buffer and return the
/// packed `(ptr << 32) | len` the host reads, or `0` for no response.
#[doc(hidden)]
pub fn __return_response(resp: Option<PluginResponse>) -> u64 {
    let Some(resp) = resp else {
        return 0;
    };
    let json = match serde_json::to_vec(&resp) {
        Ok(j) => j,
        Err(_) => return 0,
    };
    let len = json.len() as u32;
    let ptr = __alloc(len);
    if ptr == 0 {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(json.as_ptr(), ptr as usize as *mut u8, len as usize) };
    ((ptr as u64) << 32) | (len as u64)
}

/// Serialize a manifest into a guest buffer and return the packed pointer
/// the host's `metadata()` call reads. Used by [`plugin_manifest!`].
#[doc(hidden)]
pub fn __return_metadata(meta: &PluginMetadata) -> u64 {
    let json = match serde_json::to_vec(meta) {
        Ok(j) => j,
        Err(_) => return 0,
    };
    let len = json.len() as u32;
    let ptr = __alloc(len);
    if ptr == 0 {
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(json.as_ptr(), ptr as usize as *mut u8, len as usize) };
    ((ptr as u64) << 32) | (len as u64)
}

/// Declare the plugin manifest as a typed struct. Permissions are the
/// [`PluginPermission`] enum variant names (type-checked, not strings), so
/// a typo is a compile error and your editor completes them.
///
/// The host calls the generated `metadata()` export at load time to read
/// the name, version, and — crucially — the permissions the plugin needs
/// (e.g. `UseRedis` / `UseHttp`). Fields after `version` are optional.
///
/// ```ignore
/// plugin_manifest! {
///     name: "my-plugin",
///     version: "1.0.0",
///     author: "me",
///     description: "Does a thing",
///     permissions: [UseRedis, SendMessage, Broadcast],
/// }
/// ```
#[macro_export]
macro_rules! plugin_manifest {
    (
        name: $name:expr,
        version: $version:expr
        $(, author: $author:expr)?
        $(, description: $description:expr)?
        $(, min_proxy_version: $minv:expr)?
        $(, dependencies: [ $($dep:expr),* $(,)? ])?
        $(, permissions: [ $($perm:ident),* $(,)? ])?
        $(,)?
    ) => {
        #[no_mangle]
        pub extern "C" fn metadata() -> u64 {
            #[allow(unused_mut)]
            let mut __m = $crate::PluginMetadata::new($name, $version);
            $( __m.author = ($author).into(); )?
            $( __m.description = ($description).into(); )?
            $( __m.min_proxy_version = ($minv).into(); )?
            $( __m.dependencies = ::std::vec![ $( ($dep).into() ),* ]; )?
            $( __m.permissions = ::std::vec![ $( $crate::PluginPermission::$perm ),* ]; )?
            $crate::__return_metadata(&__m)
        }
    };
}

/// Embed a plugin manifest in the `kojacoord_metadata` custom section as a
/// raw JSON string literal. Prefer [`plugin_manifest!`] (typed) — this
/// remains for guests that want the section form.
#[macro_export]
macro_rules! plugin_metadata {
    ($json:expr) => {
        #[used]
        #[link_section = "kojacoord_metadata"]
        static __KOJA_METADATA: [u8; $json.len()] = {
            let bytes = $json.as_bytes();
            let mut arr = [0u8; $json.len()];
            let mut i = 0;
            while i < bytes.len() {
                arr[i] = bytes[i];
                i += 1;
            }
            arr
        };
    };
}

/// Generate the C ABI exports the host expects from a type implementing
/// [`Plugin`]. `$ctor` is an expression that builds the initial instance.
#[macro_export]
macro_rules! export_plugin {
    ($ty:ty, $ctor:expr) => {
        thread_local! {
            static __KOJA_PLUGIN: ::core::cell::RefCell<::core::option::Option<$ty>> =
                ::core::cell::RefCell::new(::core::option::Option::None);
        }

        fn __koja_ensure() {
            __KOJA_PLUGIN.with(|c| {
                if c.borrow().is_none() {
                    *c.borrow_mut() = ::core::option::Option::Some($ctor);
                }
            });
        }

        #[no_mangle]
        pub extern "C" fn alloc(size: u32) -> u32 {
            $crate::__alloc(size)
        }

        #[no_mangle]
        pub extern "C" fn dealloc(ptr: u32, size: u32) {
            $crate::__dealloc(ptr, size)
        }

        #[no_mangle]
        pub extern "C" fn init() {
            __koja_ensure();
        }

        #[no_mangle]
        pub extern "C" fn on_enable() {
            __koja_ensure();
            __KOJA_PLUGIN.with(|c| {
                if let ::core::option::Option::Some(p) = c.borrow_mut().as_mut() {
                    $crate::Plugin::on_enable(p);
                }
            });
        }

        #[no_mangle]
        pub extern "C" fn on_disable() {
            __KOJA_PLUGIN.with(|c| {
                if let ::core::option::Option::Some(p) = c.borrow_mut().as_mut() {
                    $crate::Plugin::on_disable(p);
                }
            });
        }

        #[no_mangle]
        pub extern "C" fn handle_event(ptr: u32, len: u32) -> u64 {
            let Some(event) = $crate::__decode_event(ptr, len) else {
                return 0;
            };
            __koja_ensure();
            let resp = __KOJA_PLUGIN.with(|c| {
                c.borrow_mut()
                    .as_mut()
                    .and_then(|p| $crate::Plugin::handle_event(p, &event))
            });
            $crate::__return_response(resp)
        }
    };
}
