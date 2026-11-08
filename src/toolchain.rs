//! Locates cargo/rustup and makes sure the Windows target's standard library is installed.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

pub struct Toolchain {
    pub cargo: PathBuf,
    pub rustup: Option<PathBuf>,
}

impl Toolchain {
    pub fn find() -> Result<Self> {
        let cargo = find_tool("cargo", "CARGO").context(
            "cargo not found: install Rust with rustup (https://rustup.rs) or set the CARGO variable",
        )?;
        Ok(Self { cargo, rustup: find_tool("rustup", "RUSTUP") })
    }

    /// Installs the rust-std component for `triple` if it is missing.
    /// `dir` is the project directory, so rustup honors any toolchain override there.
    pub fn ensure_target(&self, triple: &str, dir: &Path, install: bool) -> Result<()> {
        let Some(rustup) = &self.rustup else {
            // Without rustup we can't check; the build will report a missing `core` if needed.
            eprintln!("note: rustup not found, assuming target {triple} is installed");
            return Ok(());
        };
        let out = Command::new(rustup)
            .args(["target", "list", "--installed"])
            .current_dir(dir)
            .output()
            .context("cannot run rustup")?;
        if !out.status.success() {
            bail!("`rustup target list` failed:\n{}", String::from_utf8_lossy(&out.stderr));
        }
        if String::from_utf8_lossy(&out.stdout).lines().any(|l| l.trim() == triple) {
            return Ok(());
        }
        if !install {
            bail!("target {triple} is not installed; run `rustup target add {triple}`");
        }
        eprintln!("Installing Rust target {triple} (one time)...");
        let status = Command::new(rustup)
            .args(["target", "add", triple])
            .current_dir(dir)
            .status()
            .context("cannot run rustup")?;
        if !status.success() {
            bail!("`rustup target add {triple}` failed");
        }
        Ok(())
    }
}

/// Finds `name` from the `var` environment variable, then PATH, then the cargo home.
fn find_tool(name: &str, var: &str) -> Option<PathBuf> {
    if let Some(p) = env::var_os(var).map(PathBuf::from).filter(|p| p.is_file()) {
        return Some(p);
    }
    let exe = format!("{name}{}", env::consts::EXE_SUFFIX);
    let path_dirs = env::var_os("PATH").map(|p| env::split_paths(&p).collect::<Vec<_>>()).unwrap_or_default();
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(|h| PathBuf::from(h).join(".cargo")));
    path_dirs
        .into_iter()
        .chain(cargo_home.map(|h| h.join("bin")))
        .map(|d| d.join(&exe))
        .find(|p| p.is_file())
}
