//! Runs cargo on the generated project and returns the built binary.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::cli::Format;

/// Builds the project in `dir` and returns the path of the produced exe/dll.
///
/// `target_dir` is shared between runs so windows-sys is compiled only once per target.
pub fn build(cargo: &Path, dir: &Path, target_dir: &Path, triple: &str, format: Format, verbose: bool) -> Result<PathBuf> {
    let mut cmd = Command::new(cargo);
    cmd.args(["build", "--release"]).current_dir(dir).env("CARGO_TARGET_DIR", target_dir);
    // Don't let the caller's environment override the project's own configuration.
    for (key, _) in env::vars_os() {
        let Some(key) = key.to_str() else { continue };
        let drop = matches!(key, "RUSTFLAGS" | "CARGO_ENCODED_RUSTFLAGS" | "CARGO_BUILD_RUSTFLAGS" | "RG_TARGET" | "INJECT_PROC")
            || key.starts_with("CARGO_BUILD_")
            || (key.starts_with("CARGO_TARGET_") && key != "CARGO_TARGET_DIR");
        if drop {
            cmd.env_remove(key);
        }
    }

    if verbose {
        let status = cmd.status().context("cannot run cargo")?;
        if !status.success() {
            bail!("cargo build failed");
        }
    } else {
        let out = cmd.stdout(Stdio::null()).output().context("cannot run cargo")?;
        if !out.status.success() {
            bail!("cargo build failed:\n{}", String::from_utf8_lossy(&out.stderr));
        }
    }

    let artifact = target_dir.join(triple).join("release").join(format!("stager.{}", format.extension()));
    if !artifact.is_file() {
        bail!("build succeeded but {} is missing", artifact.display());
    }
    Ok(artifact)
}
