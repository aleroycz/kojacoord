//! WASM plugin sandbox configuration.
//!
//! Per-plugin policy that controls what host imports the wasmtime
//! linker exposes — filesystem reads, network sockets, child
//! processes. Defaults deny everything except the proxy's own
//! per-plugin command channel. Operators relax permissions per plugin
//! in the config; the host enforces them by simply not adding the
//! corresponding host imports to the linker for that module.

use anyhow::Result;
use log::{info, warn};

pub struct SandboxConfig {
    pub allow_filesystem: bool,
    pub allow_network: bool,
    pub allow_process_spawn: bool,
    pub restricted_paths: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            allow_filesystem: false,
            // Deny by default: a plugin must be explicitly granted network access.
            allow_network: false,
            allow_process_spawn: false,
            restricted_paths: vec![
                "/etc".to_string(),
                "/sys".to_string(),
                "/proc".to_string(),
                "/root".to_string(),
                "C:\\Windows".to_string(),
                "C:\\System32".to_string(),
            ],
        }
    }
}

pub fn apply_sandbox(_config: &SandboxConfig) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        apply_linux_sandbox(_config)?;
    }

    #[cfg(target_os = "macos")]
    {
        apply_macos_sandbox(_config)?;
    }

    #[cfg(windows)]
    {
        apply_windows_sandbox(_config)?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_linux_sandbox(config: &SandboxConfig) -> Result<()> {
    // RLIMIT_NOFILE and RLIMIT_NPROC are removed: they are process-wide
    // resource limits that cannot be applied per-thread on Linux. Setting
    // them here would cripple the proxy's own networking (NOFILE=64) and
    // child-process spawning (NPROC=0). Use containers or namespaces for
    // per-plugin isolation instead.

    if !config.allow_filesystem {
        warn!("Filesystem access restricted - requires namespace/chroot isolation");
    }

    if std::fs::metadata("/proc/self/seccomp").is_ok() {
        info!("seccomp available - advanced sandboxing possible");

        if !config.allow_network {
            warn!("Network restriction requested - requires libseccomp for full implementation");
        }
    }

    // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, ...)` only takes scalar arguments and
    // sets a per-thread flag. It has no pointer operands and cannot cause UB;
    // the return value is checked.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            warn!(
                "Failed to set no_new_privs: {}",
                std::io::Error::last_os_error()
            );
        } else {
            info!("Set no_new_privs to prevent privilege escalation");
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_macos_sandbox(config: &SandboxConfig) -> Result<()> {
    if std::fs::metadata("/System/Library/Sandbox").is_ok() {
        info!("macOS Sandbox framework available");
    }

    if !config.allow_filesystem {
        // RLIMIT_NOFILE is process-wide on macOS as well; setting it here
        // would limit the proxy's own file descriptors, not just the plugin's.
        warn!("Filesystem access restricted - macOS sandbox requires proper entitlements");
    }

    Ok(())
}

#[cfg(windows)]
fn apply_windows_sandbox(config: &SandboxConfig) -> Result<()> {
    if !config.allow_filesystem {
        warn!("Filesystem access restricted - Windows sandbox requires AppContainer");

        info!("Windows sandboxing limited - run in container for full isolation");
    }

    Ok(())
}

pub fn validate_plugin_permissions(
    requested: &SandboxConfig,
    allowed: &SandboxConfig,
) -> Result<()> {
    if requested.allow_filesystem && !allowed.allow_filesystem {
        anyhow::bail!("Plugin requests filesystem access but it is not allowed");
    }

    if requested.allow_network && !allowed.allow_network {
        anyhow::bail!("Plugin requests network access but it is not allowed");
    }

    if requested.allow_process_spawn && !allowed.allow_process_spawn {
        anyhow::bail!("Plugin requests process spawning but it is not allowed");
    }

    Ok(())
}
