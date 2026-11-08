//! Minimal PE parser for extracting the .text section as a shellcode blob.

use anyhow::{bail, Result};

/// Extract the .text section from a PE file and return it as a shellcode blob.
///
/// A 5-byte `JMP rel32` stub is prepended when the PE's entry point is not at
/// offset 0 of the section (common with LTO code layout), so the returned bytes
/// are always executable starting at byte 0.
pub fn extract_shellcode(pe: &[u8]) -> Result<Vec<u8>> {
    if pe.len() < 0x40 {
        bail!("file too small to be a PE");
    }

    // DOS header: e_lfanew at offset 0x3C
    let e_lfanew = u32::from_le_bytes(pe[0x3c..0x40].try_into()?) as usize;
    if e_lfanew + 24 > pe.len() || &pe[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        bail!("not a valid PE file");
    }

    // FileHeader: NumberOfSections at +6, SizeOfOptionalHeader at +20
    let num_sections = u16::from_le_bytes(pe[e_lfanew + 6..e_lfanew + 8].try_into()?) as usize;
    let opt_size     = u16::from_le_bytes(pe[e_lfanew + 20..e_lfanew + 22].try_into()?) as usize;

    // OptionalHeader: AddressOfEntryPoint at +16 (PE32+)
    let opt_off = e_lfanew + 24;
    if opt_off + opt_size > pe.len() || opt_size < 20 {
        bail!("PE optional header too short");
    }
    let entry_rva = u32::from_le_bytes(pe[opt_off + 16..opt_off + 20].try_into()?);

    // Section headers follow the optional header
    let section_base = opt_off + opt_size;

    for i in 0..num_sections {
        let hdr = section_base + i * 40;
        if hdr + 40 > pe.len() { break; }

        let name = &pe[hdr..hdr + 8];
        // Section is .text if name is ".text\0\0\0"
        if &name[..5] != b".text" || (name[5] != 0 && name[5] != b'$') {
            continue;
        }

        let virt_size  = u32::from_le_bytes(pe[hdr + 8..hdr + 12].try_into()?) as usize;
        let virt_addr  = u32::from_le_bytes(pe[hdr + 12..hdr + 16].try_into()?) as usize;
        let raw_size   = u32::from_le_bytes(pe[hdr + 16..hdr + 20].try_into()?) as usize;
        let raw_offset = u32::from_le_bytes(pe[hdr + 20..hdr + 24].try_into()?) as usize;

        if raw_offset + raw_size > pe.len() {
            bail!(".text section extends past end of file");
        }

        // VirtualSize can be less than SizeOfRawData (file padding); trim trailing zeros.
        let actual = if virt_size > 0 && virt_size < raw_size { virt_size } else { raw_size };
        let text = &pe[raw_offset..raw_offset + actual];

        // Calculate the entry point's offset within the .text section.
        let entry_rva = entry_rva as usize;
        if entry_rva < virt_addr || entry_rva >= virt_addr + actual {
            bail!("entry point RVA 0x{entry_rva:x} is outside .text section (VA 0x{virt_addr:x}..0x{:x})", virt_addr + actual);
        }
        let entry_off = entry_rva - virt_addr;

        if entry_off == 0 {
            // Entry is already at the start; return raw bytes.
            return Ok(text.to_vec());
        }

        // Prepend a 5-byte E9 rel32 JMP so that execution at byte 0 reaches entry.
        // After prepending 5 bytes, entry moves to offset (5 + entry_off).
        // rel32 = target − (jmp_addr + 5) = (5 + entry_off) − (0 + 5) = entry_off
        let mut sc = Vec::with_capacity(5 + actual);
        sc.push(0xE9u8);
        sc.extend_from_slice(&(entry_off as i32).to_le_bytes());
        sc.extend_from_slice(text);
        return Ok(sc);
    }

    bail!("no .text section found in PE");
}
