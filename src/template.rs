//! The generated program's template: built in (embedded at compile time) or a user directory.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Files of `template/`, embedded so the generator is a single self-contained binary.
const BUILTIN: &[(&str, &[u8])] = &[
    ("Cargo.toml", include_bytes!("../template/Cargo.toml")),
    ("Cargo.lock", include_bytes!("../template/Cargo.lock")),
    ("build.rs", include_bytes!("../template/build.rs")),
    (".cargo/config.toml", include_bytes!("../template/.cargo/config.toml")),
    ("src/stager.rs", include_bytes!("../template/src/stager.rs")),
    ("payload.bin", include_bytes!("../template/payload.bin")),
];

pub enum Template {
    Builtin,
    Dir(PathBuf),
}

impl Template {
    /// Copies the template into `dest` (which must exist).
    pub fn write_to(&self, dest: &Path) -> Result<()> {
        match self {
            Template::Builtin => write_builtin(dest),
            Template::Dir(src) => {
                if !src.join("Cargo.toml").is_file() {
                    bail!("{} is not a template (no Cargo.toml)", src.display());
                }
                copy_dir(src, dest)
            }
        }
    }
}

fn write_builtin(dest: &Path) -> Result<()> {
    for (rel, data) in BUILTIN {
        let path = dest.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, data).with_context(|| format!("cannot write {}", path.display()))?;
    }
    Ok(())
}

/// Recursively copies `src` into `dest`, skipping build output.
fn copy_dir(src: &Path, dest: &Path) -> Result<()> {
    for entry in fs::read_dir(src).with_context(|| format!("cannot read {}", src.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "target" || name == ".git" {
            continue;
        }
        let (from, to) = (entry.path(), dest.join(&name));
        if entry.file_type()?.is_dir() {
            fs::create_dir_all(&to)?;
            copy_dir(&from, &to)?;
        } else {
            fs::copy(&from, &to).with_context(|| format!("cannot copy {}", from.display()))?;
        }
    }
    Ok(())
}

/// `--export-template`: writes the built-in template to `dir` for editing.
pub fn export(dir: &Path) -> Result<()> {
    if dir.join("Cargo.toml").exists() {
        bail!("{} already contains a Cargo.toml, refusing to overwrite", dir.display());
    }
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    write_builtin(dir)
}
