//! Generator of tiny Windows file-reader programs. See README.md.

mod builder;
mod cli;
mod pe;
mod project;
mod template;
mod toolchain;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use cli::Cli;
use project::{Source, Spec};
use template::Template;

/// The generator's (temporary) name, from Cargo.toml. Used for temp/cache directory names.
const NAME: &str = env!("CARGO_PKG_NAME");

fn main() -> ExitCode {
    let cli = Cli::try_parse_args(std::env::args_os()).unwrap_or_else(|e| e.exit());
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    if let Some(dir) = &cli.export_template {
        template::export(dir)?;
        println!("Template written to {}", dir.display());
        println!("Edit it, then generate with: {NAME} --template {} ...", dir.display());
        return Ok(());
    }

    let source = source(&cli)?;
    let template = match &cli.template {
        Some(dir) => Template::Dir(dir.clone()),
        None => Template::Builtin,
    };
    let output = cli.output.clone().unwrap_or_else(|| PathBuf::from(format!("stager.{}", cli.format.extension())));
    let triple = cli.arch.triple();

    // Project directory: the --keep one, or a temporary one removed at the end.
    let (dir, _cleanup) = match &cli.keep {
        Some(dir) => (prepare_keep_dir(dir)?, None),
        None => {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
            let dir = std::env::temp_dir().join(format!("{NAME}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
            (dir.clone(), Some(RemoveOnDrop(dir)))
        }
    };

    let spec = Spec { source: &source, format: cli.format, arch: cli.arch, deps: &cli.deps, inject_proc: cli.pid.as_deref() };
    project::write(&dir, &template, &spec)?;

    let tools = toolchain::Toolchain::find()?;
    tools.ensure_target(triple, &dir, !cli.no_install)?;

    eprintln!("Building {} for {triple}...", match cli.format {
        cli::Format::Shellcode => "shellcode",
        _ => cli.format.extension(),
    });
    let target_dir = cache_dir().join("target");
    let artifact = builder::build(&tools.cargo, &dir, &target_dir, triple, cli.format, cli.verbose)?;

    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&artifact, &output).with_context(|| format!("cannot write {}", output.display()))?;
    let size = fs::metadata(&output)?.len();
    println!("{} ({size} bytes)", output.display());
    if let Some(dir) = &cli.keep {
        println!("Project kept in {} (rebuild with `cargo build --release`)", dir.display());
    }
    Ok(())
}

fn source(cli: &Cli) -> Result<Source> {
    let s = &cli.source;
    if let Some(path) = &s.local {
        if path.is_empty() {
            bail!("--local path is empty");
        }
        return Ok(Source::Local(path.clone()));
    }
    if let Some(url) = &s.url {
        let lower = url.to_ascii_lowercase();
        if !["http://", "https://"].iter().any(|p| lower.starts_with(p)) {
            bail!("--url must start with http:// or https://");
        }
        return Ok(Source::Url(url.clone()));
    }
    if let Some(file) = &s.embed {
        if !file.is_file() {
            bail!("--embed: {} is not a file", file.display());
        }
        return Ok(Source::Embed(file.clone()));
    }
    unreachable!("clap requires one source")
}

/// A --keep directory must be new, empty, or a project generated earlier (overwritten).
fn prepare_keep_dir(dir: &Path) -> Result<PathBuf> {
    if dir.exists() {
        let ours = fs::read_to_string(dir.join("Cargo.toml")).is_ok_and(|t| t.contains("ruststager:target-begin"));
        let empty = fs::read_dir(dir)?.next().is_none();
        if !ours && !empty {
            bail!("--keep: {} is not empty and is not a generated project", dir.display());
        }
    }
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    Ok(dir.to_path_buf())
}

/// Persistent cache (shared cargo target dir), so dependencies are compiled once per target.
fn cache_dir() -> PathBuf {
    let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let base = if cfg!(windows) {
        var("LOCALAPPDATA")
    } else {
        var("XDG_CACHE_HOME").or_else(|| var("HOME").map(|h| h.join(".cache")))
    };
    base.unwrap_or_else(std::env::temp_dir).join(NAME)
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
