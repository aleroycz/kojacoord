use crate::api::{Plugin, PluginContext, PluginMetadata};
use crate::integrity::PluginVerifier;
use anyhow::{Context, Result};
use libloading::{Library, Symbol};
use std::path::Path;
use std::sync::Arc;

pub struct PluginLoader {
    libraries: Vec<(String, Library)>,
    verifier: PluginVerifier,
}

impl PluginLoader {
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

    /// Access the integrity verifier to configure trusted hashes at runtime.
    pub fn verifier_mut(&mut self) -> &mut PluginVerifier {
        &mut self.verifier
    }

    pub fn load_plugin<P: AsRef<Path>>(
        &mut self,
        path: P,
        context: &PluginContext,
    ) -> Result<(Arc<dyn Plugin>, PluginMetadata)> {
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
        // `create_plugin` returns a heap-allocated `*mut dyn Plugin` ownership
        // of which is transferred to us (reconstructed via `Arc::from_raw`).
        // The library handle is retained in `self.libraries` so the code backing
        // the returned `Arc` stays mapped for the plugin's lifetime.
        unsafe {
            let library = Library::new(path).context("Failed to load plugin library")?;

            let get_metadata: Symbol<unsafe extern "C" fn() -> PluginMetadata> = library
                .get(b"get_metadata")
                .context("Missing get_metadata symbol")?;

            let metadata = get_metadata();

            if !self.check_version_compatibility(&metadata.min_proxy_version) {
                return Err(anyhow::anyhow!(
                    "Plugin requires proxy version {}, current is {}",
                    metadata.min_proxy_version,
                    env!("CARGO_PKG_VERSION")
                ));
            }

            let create_plugin: Symbol<unsafe extern "C" fn() -> *mut dyn Plugin> = library
                .get(b"create_plugin")
                .context("Missing create_plugin symbol")?;

            let plugin_ptr = create_plugin();
            let mut plugin = Arc::from_raw(plugin_ptr);

            Arc::get_mut(&mut plugin)
                .ok_or_else(|| anyhow::anyhow!("Failed to get mutable reference to plugin"))?
                .on_load(context)?;

            self.libraries.push((metadata.name.clone(), library));

            Ok((plugin, metadata))
        }
    }

    pub fn unload_all(&mut self) {
        self.libraries.clear();
    }

    fn check_version_compatibility(&self, required: &str) -> bool {
        let current = env!("CARGO_PKG_VERSION");
        current >= required
    }
}

impl Default for PluginLoader {
    fn default() -> Self {
        Self::new()
    }
}
