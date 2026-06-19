use anyhow::Context;
use flate2::{write::GzEncoder, Compression};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Rotate previous latest.log to logs/YYYY-MM-DD_HH-MM-SS.log.gz
    rotate_previous_log();

    std::fs::create_dir_all("logs").context("Failed to create logs directory")?;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("logs/latest.log")
        .context("Failed to open logs/latest.log")?;

    let (non_blocking, _guard) = tracing_appender::non_blocking(file);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,kojacoord=info".parse().expect("valid filter"));

    use tracing_subscriber::prelude::*;
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_ansi(true))           // console
        .with(tracing_subscriber::fmt::layer()                            // file
            .with_ansi(false)
            .with_writer(non_blocking))
        .with(BreadcrumbLayer)                                            // crash-report trail
        .init();

    // Install the crash-report panic hook as early as possible so a panic on
    // any thread (including the tokio worker pool spawned below) is captured
    // into logs/crash-report-<timestamp>.txt. The breadcrumb layer above
    // feeds the "last actions" section from ordinary log events.
    kojacoord_proxy_core::crash_report::install_panic_hook();

    tracing::info!("KojacoordProxy starting…");

    // Best-effort update check against the KojaCraft release API. Spawned
    // so a slow/unreachable network never delays startup.
    tokio::spawn(async {
        kojacoord_proxy_core::version_check::check_for_updates(env!("CARGO_PKG_VERSION")).await;
    });

    // Standard startup flow: load config, initialise state, spawn background tasks.
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_owned());

    let mut config = if std::path::Path::new(&config_path).exists() {
        kojacoord_config::ProxyConfig::from_file(&config_path)
            .with_context(|| format!("Failed to load config from {}", config_path))?
    } else {
        tracing::warn!("{} not found — writing default config", config_path);
        // Start from defaults, then auto-generate strong secrets for any enabled
        // control plane so the first run is secure-by-default (no `changeme`).
        let mut cfg: kojacoord_config::ProxyConfig =
            toml::from_str(kojacoord_config::DEFAULT_CONFIG)
                .context("Failed to parse embedded default config")?;
        if cfg.ensure_secrets() {
            tracing::warn!(
                "Generated strong random auth tokens for enabled control-plane services; \
                 see {} for the values.",
                config_path
            );
        }
        save_config(&cfg, &config_path).context("Failed to write default config")?;
        cfg.validate()
            .context("Generated default config failed validation")?;
        cfg
    };

    // Check EULA acceptance
    if !config.proxy.eula_accepted {
        println!("\n=== Minecraft EULA ===");
        println!("By using the Minecraft server software, you agree to the Minecraft EULA");
        println!("https://www.minecraft.net/en-us/eula");
        println!("\nDo you agree to the Minecraft EULA? (yes/no): ");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        let input = input.trim().to_lowercase();
        if input == "yes" || input == "y" {
            config.proxy.eula_accepted = true;
            save_config(&config, &config_path)?;
            println!("EULA accepted and saved to config.");
        } else {
            eprintln!("EULA not accepted. Exiting.");
            std::process::exit(1);
        }
    }

    tracing::info!(
        "Config loaded: bind={} online_mode={} server_id={}",
        config.proxy.bind,
        config.proxy.online_mode,
        config.proxy.server_id
    );

    let state = Arc::new(
        kojacoord_proxy_core::proxy::ProxyState::new(config)
            .await
            .context("Failed to initialize proxy state")?,
    );

    // Seed the crash report with a curated, secret-free snapshot of this
    // run. Never include tokens, the DB URL, or keys here — the report is
    // meant to be shareable.
    {
        let plugins_loaded = state
            .plugin_manager
            .read()
            .map(|m| m.loaded_plugins().len())
            .unwrap_or(0);
        kojacoord_proxy_core::crash_report::set_metadata(
            kojacoord_proxy_core::crash_report::CrashMetadata {
                version: env!("CARGO_PKG_VERSION").to_string(),
                server_id: state.config.proxy.server_id.clone(),
                bind: state.config.proxy.bind.clone(),
                online_mode: state.config.proxy.online_mode,
                max_players: state.config.proxy.max_players,
                plugins_loaded,
                started_at: state.started_at,
            },
        );
    }

    // Start listening to plugin command channels.
    state.start_plugin_command_processors();

    // Deliver Redis subscribe messages to WASM plugins on a short interval.
    state.start_wasm_redis_pump();

    // Polling hot-reload watcher (no-op when plugins.hot_reload = false).
    state.start_plugin_hot_reload_watcher();

    // Anonymous, opt-out usage telemetry (metric.kojacoord.net). Honours
    // [telemetry] enabled in the config; never blocks or fails the proxy.
    kojacoord_proxy_core::telemetry::spawn(Arc::clone(&state));

    // Watch the config file for changes and hot-reload the server list
    // without restarting the proxy.
    let watcher_state = Arc::clone(&state);
    let watcher_path = config_path.clone();
    tokio::task::spawn_blocking(move || {
        use notify::{EventKind, RecursiveMode, Watcher};
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match notify::recommended_watcher(move |res| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create config file watcher");
                return;
            },
        };

        let config_path_buf = std::path::PathBuf::from(&watcher_path);
        let parent_dir = config_path_buf
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));

        if let Err(e) = watcher.watch(parent_dir, RecursiveMode::NonRecursive) {
            tracing::error!(error = %e, path = %watcher_path, "Failed to register file watch");
            return;
        }

        tracing::info!(path = %watcher_path, "Config file watcher active");

        for event in rx {
            let target_modified = event
                .paths
                .iter()
                .any(|p| p.file_name() == config_path_buf.file_name());

            if target_modified && matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_))
            {
                std::thread::sleep(std::time::Duration::from_millis(100));
                match kojacoord_config::ProxyConfig::from_file(&watcher_path) {
                    Ok(new_cfg) => {
                        tracing::info!("Config file modified, hot-reloading full configuration...");
                        let st = Arc::clone(&watcher_state);
                        tokio::spawn(async move {
                            st.reload_config(&new_cfg).await;
                        });
                    },
                    Err(e) => {
                        tracing::error!(error = %e, path = %watcher_path, "Failed to parse modified config file");
                    },
                }
            }
        }
    });

    // SIGHUP signal handler for Unix systems to trigger config reload
    #[cfg(unix)]
    {
        use tokio::signal::unix;
        let sighup_state = Arc::clone(&state);
        let sighup_path = config_path.clone();
        tokio::spawn(async move {
            let mut sigterm = unix::signal(unix::SignalKind::hangup()).unwrap();
            loop {
                sigterm.recv().await;
                tracing::info!("Received SIGHUP signal, reloading configuration...");
                match kojacoord_config::ProxyConfig::from_file(&sighup_path) {
                    Ok(new_cfg) => {
                        sighup_state.reload_config(&new_cfg).await;
                    },
                    Err(e) => {
                        tracing::error!(error = %e, path = %sighup_path, "Failed to reload config on SIGHUP");
                    },
                }
            }
        });
    }

    // Graceful shutdown. We race `accept_loop` against signal handlers
    // so any way out — Ctrl+C, SIGTERM, panic that propagates up — runs
    // the same disconnect-all path. The reason JSON is the literal
    // string the client should see in its disconnect dialog.
    //
    // Why a hardcoded reason instead of pulling from config: the
    // shutdown can fire before the config is reachable (early panic,
    // failed reload swap, etc.). A static string is always safe and
    // matches the spec the user gave us verbatim.
    let shutdown_state = Arc::clone(&state);
    // Inlined to avoid pulling in a workspace dep here — the literal
    // is what the client will render verbatim. Single quotes inside
    // values are JSON-safe.
    let shutdown_reason =
        r#"{"text":"Proxy is restarting, Please try again later.","color":"yellow"}"#.to_string();

    let accept_fut = kojacoord_proxy_core::proxy::accept_loop(state);

    // Signal aggregator. Ctrl+C is portable; SIGTERM and SIGQUIT are
    // Unix-only and only registered on those targets. Whichever fires
    // first wins — the others are dropped on the floor.
    let signal_fut = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).ok();
            let mut quit = signal(SignalKind::quit()).ok();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => "Ctrl+C",
                _ = async {
                    match term.as_mut() {
                        Some(s) => { s.recv().await; },
                        None => std::future::pending::<()>().await,
                    }
                } => "SIGTERM",
                _ = async {
                    match quit.as_mut() {
                        Some(s) => { s.recv().await; },
                        None => std::future::pending::<()>().await,
                    }
                } => "SIGQUIT",
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            "Ctrl+C"
        }
    };

    let result = tokio::select! {
        r = accept_fut => {
            tracing::warn!("Accept loop exited — beginning graceful shutdown");
            r
        }
        sig = signal_fut => {
            tracing::warn!(signal = sig, "Shutdown signal received");
            Ok(())
        }
    };

    // An error out of the accept loop is a crash, not a clean shutdown —
    // write a full crash report before we tear everything down.
    if let Err(ref e) = result {
        if let Some(path) =
            kojacoord_proxy_core::crash_report::report_fatal_error("Accept loop terminated", e)
        {
            tracing::error!(report = %path.display(), "Crash report written");
        }
    }

    shutdown_state.shutdown_gracefully(&shutdown_reason).await;

    // Forceful exit. After `shutdown_gracefully` returns, every
    // connection task has either flushed its Disconnect and dropped,
    // or has missed the 1.5s flush window. Background tasks (failover
    // monitor, MOTD refresh, etc.) are detached and would otherwise
    // keep the tokio runtime alive forever; `std::process::exit`
    // bypasses the runtime's "wait for all tasks" drop semantics.
    // The exit code mirrors whatever `accept_loop` produced — Ok → 0,
    // Err → 1.
    let exit_code = if result.is_ok() { 0 } else { 1 };
    tracing::info!(exit_code, "Proxy exiting");
    std::process::exit(exit_code);
}

/// A `tracing` layer that mirrors INFO/WARN/ERROR events into the crash
/// report's "last actions" breadcrumb trail. DEBUG/TRACE are skipped to keep
/// the trail focused on meaningful actions rather than per-packet noise.
struct BreadcrumbLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for BreadcrumbLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = *event.metadata().level();
        if !matches!(
            level,
            tracing::Level::INFO | tracing::Level::WARN | tracing::Level::ERROR
        ) {
            return;
        }
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        kojacoord_proxy_core::crash_report::record(format!(
            "{level:>5} {}: {}",
            event.metadata().target(),
            visitor.0.trim_end()
        ));
    }
}

/// Flattens an event's `message` + structured fields into one line.
#[derive(Default)]
struct FieldVisitor(String);

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?} ");
        } else {
            let _ = write!(self.0, "{}={value:?} ", field.name());
        }
    }
}

fn save_config(config: &kojacoord_config::ProxyConfig, path: &str) -> anyhow::Result<()> {
    let toml = toml::to_string_pretty(config)?;
    std::fs::write(path, toml)?;
    Ok(())
}

#[cfg(unix)]
#[allow(dead_code)]
fn is_running_as_elevated() -> bool {
    // SAFETY: `getuid` is a thread-safe, always-succeeding POSIX syscall that
    // takes no arguments and only reads the calling process's real user ID.
    // It has no preconditions and cannot fail or cause UB.
    unsafe { libc::getuid() == 0 }
}

#[cfg(windows)]
#[allow(dead_code)]
fn is_running_as_elevated() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: All Win32 calls below receive valid, locally-owned pointers and
    // correctly-sized buffers. `token` is a stack HANDLE we own; `elevation`
    // and `size` are stack locals whose sizes match the TokenElevation query.
    // No raw pointer outlives this block and every call's result is checked.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
            let mut elevation = 0u32;
            let mut size = std::mem::size_of::<u32>() as u32;
            if GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                size,
                &mut size,
            )
            .is_ok()
            {
                return elevation != 0;
            }
        }
        false
    }
}

#[cfg(not(any(unix, windows)))]
fn is_running_as_elevated() -> bool {
    false
}

fn rotate_previous_log() {
    let latest = std::path::Path::new("logs/latest.log");
    if !latest.exists() {
        return;
    }

    // Timestamp from file modification time, fall back to now
    let timestamp = std::fs::metadata(latest)
        .and_then(|m| m.modified())
        .map(|t| {
            let dt: chrono::DateTime<chrono::Local> = t.into();
            dt.format("%Y-%m-%d_%H-%M-%S").to_string()
        })
        .unwrap_or_else(|_| chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string());

    let _ = std::fs::create_dir_all("logs");
    let gz_path = format!("logs/{}.log.gz", timestamp);

    match (std::fs::read(latest), std::fs::File::create(&gz_path)) {
        (Ok(data), Ok(out)) => {
            let mut enc = GzEncoder::new(out, Compression::best());
            if let Err(e) =
                std::io::Write::write_all(&mut enc, &data).and_then(|_| enc.finish().map(|_| ()))
            {
                eprintln!("Failed to gzip previous log: {e}");
                return;
            }
            let _ = std::fs::remove_file(latest);
            eprintln!("Rotated previous log to {gz_path}");
        },
        (Err(e), _) => eprintln!("Could not read latest.log for rotation: {e}"),
        (_, Err(e)) => eprintln!("Could not create {gz_path}: {e}"),
    }
}
