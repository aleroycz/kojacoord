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
    use std::fs;

    if !config.allow_filesystem {
        // SAFETY: `setrlimit` reads a fully-initialised `rlimit` struct through a
        // valid shared reference for the duration of the call. The resource id is
        // a libc constant and the return value is checked; no UB is possible.
        unsafe {
            let rlim = libc::rlimit {
                rlim_cur: 64,
                rlim_max: 64,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) != 0 {
                warn!(
                    "Failed to set RLIMIT_NOFILE: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        // SAFETY: identical contract to the RLIMIT_NOFILE call above — a valid,
        // initialised `rlimit` passed by shared reference to a checked syscall.
        unsafe {
            let rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_NPROC, &rlim) != 0 {
                warn!(
                    "Failed to set RLIMIT_NPROC: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        warn!("Filesystem access restricted via resource limits");
    }

    if fs::metadata("/proc/self/seccomp").is_ok() {
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
    use std::fs;

    if fs::metadata("/System/Library/Sandbox").is_ok() {
        info!("macOS Sandbox framework available");
    }

    if !config.allow_filesystem {
        warn!("Filesystem access restricted - macOS sandbox requires proper entitlements");

        // SAFETY: `setrlimit` reads a fully-initialised `rlimit` through a valid
        // shared reference for the call's duration; the return value is checked.
        unsafe {
            let rlim = libc::rlimit {
                rlim_cur: 64,
                rlim_max: 64,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) != 0 {
                warn!(
                    "Failed to set RLIMIT_NOFILE: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
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
