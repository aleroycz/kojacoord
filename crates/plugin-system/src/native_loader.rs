//! Native (`.dll`/`.so`/`.dylib`) plugin loader.
//!
//! The [`wasm_loader`](crate::wasm_loader) runs unaudited modules inside a
//! wasmtime sandbox. This is the other half of the host promised in
//! [`crate`]'s module docs: it `dlopen`s a native dynamic library and calls
//! its C-ABI entry points (`get_metadata` / `create_plugin`). Native plugins
//! run with full process privileges — fast, and able to use tokio, sockets and
//! the filesystem directly — so loading is gated behind the SHA-256 allowlist
//! in [`integrity`](crate::integrity).
//!
//! The loaded [`libloading::Library`] handles are retained for the lifetime of
//! the loader: the `Box<dyn Plugin>` returned to the caller has a vtable that
//! points into the library's code, so the library must stay mapped until the
//! plugin instance is dropped. Callers MUST drop the plugin instance before
//! calling [`PluginLoader::unload`]/[`PluginLoader::unload_all`].

use crate::api::{Plugin, PluginContext, PluginMetadata};
use crate::integrity::PluginVerifier;
use anyhow::{Context, Result};
use libloading::{Library, Symbol};
use std::path::Path;

/// Owns the `dlopen`ed library handles backing every native plugin. Each entry
/// is keyed by the plugin's declared metadata name so individual plugins can be
/// unmapped on unload/reload.
pub struct PluginLoader {
    libraries: Vec<(String, Library)>,
    verifier: PluginVerifier,
}

impl PluginLoader {
    /// Constructs a new PluginLoader with an empty library list and a default PluginVerifier.
    ///
    /// # Examples
    ///
    /// ```
    /// let _loader = plugin_system::native_loader::PluginLoader::new();
    /// ```
    pub fn new() -> Self {
        Self {
            libraries: Vec::new(),
            verifier: PluginVerifier::new(),
        }
    }

    /// Create a loader that verifies plugin binaries against `verifier`.
    pub fn with_verifier(verifier: PluginVerifier) -> Self {
        Self {
            libraries: Vec::new(),
            verifier,
        }
    }

    /// Access the internal `PluginVerifier` for runtime configuration of trusted hashes.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut loader = PluginLoader::new();
    /// let _verifier: &mut PluginVerifier = loader.verifier_mut();
    /// ```
    pub fn verifier_mut(&mut self) -> &mut PluginVerifier {
        &mut self.verifier
    }

    /// Verify, map, and instantiate a native plugin, then run its `on_load` hook.
    ///
    /// This verifies the plugin binary using the loader's `PluginVerifier`, loads the
    /// dynamic library, invokes the plugin's C-ABI entry points to obtain metadata
    /// and an owned `Box<dyn Plugin>`, and retains the underlying library handle
    /// internally so the plugin's vtable remains valid.
    ///
    /// The caller must drop the returned `Box<dyn Plugin>` before calling
    /// `PluginLoader::unload` or `PluginLoader::unload_all` for the same plugin;
    /// unloading while plugin instances still exist will leave dangling vtable
    /// pointers.
    ///
    /// # Returns
    ///
    /// A tuple containing the owned plugin instance and the plugin's declared metadata.
    ///
    /// # Examples
    ///
    /// ```
    /// # use plugin_system::{PluginLoader, PluginContext};
    /// # use std::path::Path;
    /// let mut loader = PluginLoader::new();
    /// let ctx = PluginContext::default();
    /// let (plugin, metadata) = loader.load_plugin(Path::new("path/to/plugin.so"), &ctx).unwrap();
    /// // Use `plugin`...
    /// drop(plugin); // Drop before unloading
    /// loader.unload(&metadata.name);
    /// ```
    pub fn load_plugin<P: AsRef<Path>>(
        &mut self,
        path: P,
        context: &PluginContext,
    ) -> Result<(Box<dyn Plugin>, PluginMetadata)> {
        let path = path.as_ref();

        // Verify the binary's integrity BEFORE mapping it into the process.
        // A native plugin runs with full privileges, so an untrusted binary is
        // arbitrary code execution.
        self.verifier
            .verify(path)
            .context("plugin integrity verification failed")?;

        // SAFETY: Loading a native library and calling its FFI entry points is
        // inherently unsafe — we trust that a verified plugin exports
        // `get_metadata`/`create_plugin` with the documented C ABI and that
        // `create_plugin` returns a heap-allocated `*mut dyn Plugin` whose
        // ownership is transferred to us (reconstructed via `Box::from_raw`).
        // The library handle is retained in `self.libraries` so the code backing
        // the returned plugin stays mapped for its lifetime.
        unsafe {
            let library = Library::new(path).context("Failed to load plugin library")?;

            // `C-unwind` (not plain `C`): if a plugin's entry point panics, the
            // unwind crossing this boundary is defined behaviour that we can
            // catch below, rather than UB that segfaults the proxy. A plugin
            // built against the older `extern "C"` ABI that panics here is still
            // UB on its side — but a correctly-built one is now contained.
            let get_metadata: Symbol<unsafe extern "C-unwind" fn() -> PluginMetadata> = library
                .get(b"get_metadata")
                .context("Missing get_metadata symbol")?;

            let metadata = crate::guard_plugin_call("get_metadata", || get_metadata())
                .context("plugin get_metadata panicked")?;

            if !Self::check_version_compatibility(&metadata.min_proxy_version) {
                return Err(anyhow::anyhow!(
                    "Plugin requires proxy version {}, current is {}",
                    metadata.min_proxy_version,
                    env!("CARGO_PKG_VERSION")
                ));
            }

            let create_plugin: Symbol<unsafe extern "C-unwind" fn() -> *mut dyn Plugin> = library
                .get(b"create_plugin")
                .context("Missing create_plugin symbol")?;

            let plugin_ptr = crate::guard_plugin_call("create_plugin", || create_plugin())
                .context("plugin create_plugin panicked")?;
            if plugin_ptr.is_null() {
                return Err(anyhow::anyhow!("create_plugin returned a null pointer"));
            }
            // Own the plugin as a Box so callers can take `&mut` (needed for
            // on_load / on_enable / register_packet_hooks / handle_event).
            let mut plugin: Box<dyn Plugin> = Box::from_raw(plugin_ptr);

            crate::guard_plugin_call("on_load", || plugin.on_load(context))
                .and_then(|r| r)
                .context("plugin on_load failed")?;

            self.libraries.push((metadata.name.clone(), library));

            Ok((plugin, metadata))
        }
    }

    /// Unload the retained native library associated with a plugin metadata name.
    ///
    /// Calling this removes the stored `libloading::Library` handle for `name`, allowing the library to be
    /// unmapped when no other handles remain. The caller must drop the corresponding `Box<dyn Plugin>`
    /// before calling this method because the plugin's vtable points into the library's code.
    /// Calling with a name that is not present is a safe no-op.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut loader = PluginLoader::new();
    /// // Safe to call for names not loaded; does nothing in that case.
    /// loader.unload("example_plugin");
    /// ```
    pub fn unload(&mut self, name: &str) {
        self.libraries.retain(|(n, _)| n != name);
    }

    /// Unloads all retained native plugin libraries.
    ///
    /// Clears the loader's internal list of mapped libraries, causing their native handles
    /// to be dropped and the libraries to be unmapped. Callers must drop any plugin
    /// instances that reference those libraries before calling this method; otherwise
    /// those instances' vtables may reference unmapped code.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut loader = PluginLoader::new();
    /// // safe to call even if no plugins are loaded
    /// loader.unload_all();
    /// ```
    pub fn unload_all(&mut self) {
        self.libraries.clear();
    }

    /// Checks whether the current crate version meets or exceeds a minimum required version.
    ///
    /// Compares the package version of the current crate to `required` using string comparison and
    /// returns whether the current version is greater than or equal to `required`.
    ///
    /// # Examples
    ///
    /// ```
    /// // This should be true for any real crate version (>= "0.0.0").
    /// assert!(check_version_compatibility("0.0.0"));
    /// ```
    fn check_version_compatibility(required: &str) -> bool {
        let current = env!("CARGO_PKG_VERSION");
        current >= required
    }
}

impl Default for PluginLoader {
    /// Creates a default PluginLoader backed by a new PluginVerifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::native_loader::PluginLoader;
    /// let _loader = PluginLoader::default();
    /// ```
    fn default() -> Self {
        Self::new()
    }
}
