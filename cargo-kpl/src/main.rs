use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "cargo-kpl")]
#[command(about = "Build Kojacoord plugins (.kpl files)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a plugin from the current directory
    Build {
        /// Output path for the .kpl file (default: target/<plugin-name>.kpl)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Plugin name (default: from Cargo.toml)
        #[arg(short, long)]
        name: Option<String>,

        /// Release build
        #[arg(short, long)]
        release: bool,
    },
    /// Package an existing compiled library into .kpl
    Package {
        /// Path to the compiled library (.dll, .so, or .dylib)
        #[arg(short, long)]
        input: PathBuf,

        /// Output path for the .kpl file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Plugin metadata file (optional)
        #[arg(short, long)]
        metadata: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Build {
            output,
            name,
            release,
        } => build_plugin(output, name, release),
        Commands::Package {
            input,
            output,
            metadata,
        } => package_plugin(input, output, metadata),
    }
}

fn build_plugin(output: Option<PathBuf>, name: Option<String>, release: bool) -> Result<()> {
    println!("Building Kojacoord plugin...");

    // Read Cargo.toml to get plugin metadata
    let cargo_toml = fs::read_to_string("Cargo.toml").context("Failed to read Cargo.toml")?;

    let cargo_config: CargoConfig =
        toml::from_str(&cargo_toml).context("Failed to parse Cargo.toml")?;

    let plugin_name = name.unwrap_or_else(|| cargo_config.package.name.clone());

    // Build the library
    println!("Compiling plugin library...");
    let mut cmd = std::process::Command::new("cargo");
    cmd.args(["build"]);
    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("Failed to run cargo build")?;

    if !status.success() {
        anyhow::bail!("Cargo build failed");
    }

    // Find the compiled library
    let target_dir = PathBuf::from("target");
    let profile = if release { "release" } else { "debug" };

    let lib_path = find_library(&target_dir.join(profile), &plugin_name)
        .context("Failed to find compiled library")?;

    println!("Found library: {:?}", lib_path);

    // Create plugin metadata
    let plugin_metadata = PluginMetadata {
        name: plugin_name.clone(),
        version: cargo_config.package.version,
        author: cargo_config
            .package
            .authors
            .first()
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string()),
        description: cargo_config
            .package
            .description
            .unwrap_or_else(|| "A Kojacoord plugin".to_string()),
        min_proxy_version: "0.1.0".to_string(),
        dependencies: vec![],
    };

    // Package into .kpl file
    let output_path = output.unwrap_or_else(|| target_dir.join(format!("{}.kpl", plugin_name)));
    package_to_kpl(&lib_path, &plugin_metadata, &output_path)?;

    println!("Plugin built successfully: {:?}", output_path);
    Ok(())
}

fn package_plugin(
    input: PathBuf,
    output: Option<PathBuf>,
    metadata: Option<PathBuf>,
) -> Result<()> {
    println!("Packaging plugin into .kpl file...");

    let plugin_metadata = if let Some(metadata_path) = metadata {
        let metadata_content =
            fs::read_to_string(&metadata_path).context("Failed to read metadata file")?;
        toml::from_str(&metadata_content).context("Failed to parse metadata file")?
    } else {
        // Try to infer from library name
        let lib_name = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("plugin");
        PluginMetadata {
            name: lib_name.to_string(),
            version: "1.0.0".to_string(),
            author: "Unknown".to_string(),
            description: "A Kojacoord plugin".to_string(),
            min_proxy_version: "0.1.0".to_string(),
            dependencies: vec![],
        }
    };

    let output_path = output.unwrap_or_else(|| {
        let mut path = input.clone();
        path.set_extension("kpl");
        path
    });

    package_to_kpl(&input, &plugin_metadata, &output_path)?;

    println!("Plugin packaged successfully: {:?}", output_path);
    Ok(())
}

fn package_to_kpl(
    lib_path: &PathBuf,
    metadata: &PluginMetadata,
    output_path: &PathBuf,
) -> Result<()> {
    let file = fs::File::create(output_path).context("Failed to create output file")?;
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    // Add metadata
    let metadata_json = serde_json::to_string_pretty(metadata)?;
    zip.start_file("metadata.json", options)?;
    zip.write_all(metadata_json.as_bytes())?;

    // Add library
    let lib_name = lib_path
        .file_name()
        .and_then(|s| s.to_str())
        .context("Failed to get library filename")?;
    let lib_data = fs::read(lib_path).context("Failed to read library file")?;
    zip.start_file(lib_name, options)?;
    zip.write_all(&lib_data)?;

    // Add any additional files (config, etc.)
    if PathBuf::from("plugin.toml").exists() {
        let config_data = fs::read("plugin.toml").context("Failed to read plugin.toml")?;
        zip.start_file("plugin.toml", options)?;
        zip.write_all(&config_data)?;
    }

    zip.finish()?;
    Ok(())
}

fn find_library(dir: &PathBuf, name: &str) -> Result<PathBuf> {
    let extensions = if cfg!(windows) {
        vec![".dll", ".lib"]
    } else if cfg!(target_os = "macos") {
        vec![".dylib", ".so"]
    } else {
        vec![".so"]
    };

    for entry in WalkDir::new(dir).max_depth(2) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let Some(file_name) = entry.file_name().to_str() else {
                continue;
            };
            for ext in &extensions {
                if (file_name.starts_with(&format!("lib{}", name)) || file_name.starts_with(name))
                    && file_name.ends_with(ext)
                {
                    return Ok(entry.path().to_path_buf());
                }
            }
        }
    }

    anyhow::bail!("Library not found for name: {}", name)
}

#[derive(serde::Deserialize)]
struct CargoConfig {
    package: Package,
}

#[derive(serde::Deserialize)]
struct Package {
    name: String,
    version: String,
    authors: Vec<String>,
    description: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PluginMetadata {
    name: String,
    version: String,
    author: String,
    description: String,
    min_proxy_version: String,
    dependencies: Vec<String>,
}
