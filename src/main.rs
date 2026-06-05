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

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        "kojacoord=info,warn,trace,debug"
            .parse()
            .expect("valid filter")
    });

    use tracing_subscriber::prelude::*;
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_ansi(true))           // console
        .with(tracing_subscriber::fmt::layer()                            // file
            .with_ansi(false)
            .with_writer(non_blocking))
        .init();

    tracing::info!("KojacoordProxy starting…");

    // rest of your main unchanged below
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

    // Embedded dashboard API. Runs in-process so it serves live proxy state
    // (online sessions, backend registry, live kicks) over HTTP. Spawned only
    // when a dashboard config is present; its failure never stops the proxy.
    let dash_config = "dashboard.toml";
    if std::path::Path::new(dash_config).exists() {
        let dash_state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = kojacoord_dashboard_api::serve(dash_state, dash_config).await {
                tracing::error!(error = %e, "dashboard API stopped");
            }
        });
    } else {
        tracing::info!("{} not found — dashboard API disabled", dash_config);
    }

    // Anonymous, opt-out usage telemetry (metric.kojacoord.net). Honours
    // [telemetry] enabled in the config; never blocks or fails the proxy.
    kojacoord_proxy_core::telemetry::spawn(Arc::clone(&state));

    kojacoord_proxy_core::proxy::accept_loop(state).await
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
