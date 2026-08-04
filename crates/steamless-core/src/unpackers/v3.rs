use crate::crypto::{steam_drmp_decrypt_pass1, steam_xor, AesHelper, CipherMode};
use crate::pattern::find_pattern;
use crate::pe::{Pe32File, Pe64File, PeFile};
use super::headers::{
    SteamStub32Var30Header, SteamStub32Var31Header, SteamStub64Var30Header, SteamStub64Var31Header,
};
use super::UnpackerPlugin;

pub struct V3HeaderFields {
    pub header_size: usize,
    pub signature: u32,
    pub original_entry_point: u64,
    pub bind_section_offset: u32,
    pub payload_size: u32,
    pub drmp_dll_offset: u32,
    pub drmp_dll_size: u32,
    pub steam_app_id: u32,
    pub flags: u32,
    pub code_section_virtual_address: u64,
    pub aes_key: [u8; 32],
    pub aes_iv: [u8; 16],
    pub code_section_stolen_data: [u8; 16],
    pub encryption_keys: [u32; 4],
}

pub fn unpack_v3_64<F>(
    pe64: &Pe64File,
    output_path: &str,
    plugin_name: &str,
    header_parser: F,
) -> Result<(), String>
where
    F: Fn(&[u8]) -> Result<V3HeaderFields, String>,
{
    let ep_file_offset = pe64.get_file_offset_from_rva(pe64.entry_point)?;
    let mut header_bytes = pe64.raw_data[ep_file_offset.saturating_sub(0x100)..ep_file_offset].to_vec();
    let mut xor_key = steam_xor(&mut header_bytes, 0);
    let mut fields = header_parser(&header_bytes)?;

    let mut tls_as_oep = false;
    let mut tls_oep_rva = 0u32;

    if fields.signature != 0xC0DEC0DF && fields.signature != 0xC0DEC0DE {
        if pe64.tls_callbacks.is_empty() {
            return Err(format!("Invalid SteamStub DRM header signature: 0x{:08X}", fields.signature));
        }

        let tls_rva = pe64.get_rva_from_va(pe64.tls_callbacks[0]);
        let tls_offset = pe64.get_file_offset_from_rva(tls_rva)?;
        header_bytes = pe64.raw_data[tls_offset.saturating_sub(0x100)..tls_offset].to_vec();
        xor_key = steam_xor(&mut header_bytes, 0);
        fields = header_parser(&header_bytes)?;

        if fields.signature != 0xC0DEC0DF && fields.signature != 0xC0DEC0DE {
            return Err(format!("Invalid SteamStub DRM header signature (TLS fallback): 0x{:08X}", fields.signature));
        }

        tls_as_oep = true;
        tls_oep_rva = tls_rva;
    }

    println!("[{}] Header validated successfully.", plugin_name);
    println!("  Original Entry Point: 0x{:016X}", fields.original_entry_point);
    println!("  Steam AppID:          {}", fields.steam_app_id);

    let oep_base_rva = if tls_as_oep { tls_oep_rva } else { pe64.entry_point };
    let payload_rva = oep_base_rva.saturating_sub(fields.bind_section_offset);
    let payload_size = (fields.payload_size + 0x0F) & !0x0F;

    if payload_size > 0 {
        if let Ok(payload_offset) = pe64.get_file_offset_from_rva(payload_rva) {
            if payload_offset + payload_size as usize <= pe64.raw_data.len() {
                let mut payload = pe64.raw_data[payload_offset..payload_offset + payload_size as usize].to_vec();
                steam_xor(&mut payload, xor_key);
            }
        }
    }

    if fields.drmp_dll_size > 0 {
        let drmp_rva = payload_rva + fields.drmp_dll_offset;
        if let Ok(drmp_offset) = pe64.get_file_offset_from_rva(drmp_rva) {
            if drmp_offset + fields.drmp_dll_size as usize <= pe64.raw_data.len() {
                let mut drmp_data = pe64.raw_data[drmp_offset..drmp_offset + fields.drmp_dll_size as usize].to_vec();
                steam_drmp_decrypt_pass1(&mut drmp_data, &fields.encryption_keys);
            }
        }
    }

    let mut decrypted_code: Option<Vec<u8>> = None;
    let mut code_sec_idx: Option<usize> = None;

    let no_encryption = (fields.flags & 1) != 0;
    if !no_encryption {
        if let Some(idx) = pe64.get_owner_section_index(fields.code_section_virtual_address) {
            code_sec_idx = Some(idx);
            let sec = &pe64.sections[idx];
            let raw_size = sec.header.size_of_raw_data as usize;

            if raw_size > 0 {
                let stolen_data = fields.code_section_stolen_data;
                let stolen_len = stolen_data.len();
                let sec_file_offset = pe64.get_file_offset_from_rva(sec.header.virtual_address)?;

                let mut code_data = vec![0u8; raw_size + stolen_len];
                code_data[..stolen_len].copy_from_slice(&stolen_data);
                let sec_end = (sec_file_offset + raw_size).min(pe64.raw_data.len());
                let copy_size = sec_end.saturating_sub(sec_file_offset);
                code_data[stolen_len..stolen_len + copy_size].copy_from_slice(&pe64.raw_data[sec_file_offset..sec_file_offset + copy_size]);

                let mut aes = AesHelper::new(&fields.aes_key, &fields.aes_iv, CipherMode::CBC);
                aes.rebuild_iv(&fields.aes_iv);

                let decrypted = aes.decrypt(&code_data, CipherMode::CBC);
                decrypted_code = Some(decrypted[..raw_size].to_vec());
            }
        }
    }

    let new_entry_point = pe64.get_rva_from_va(fields.original_entry_point);
    pe64.save_unpacked(output_path, new_entry_point, code_sec_idx, decrypted_code.as_deref(), true)?;

    Ok(())
}

pub fn unpack_v3_32<F>(
    pe32: &Pe32File,
    output_path: &str,
    plugin_name: &str,
    header_parser: F,
) -> Result<(), String>
where
    F: Fn(&[u8]) -> Result<V3HeaderFields, String>,
{
    let ep_file_offset = pe32.get_file_offset_from_rva(pe32.entry_point)?;
    let mut header_bytes = pe32.raw_data[ep_file_offset.saturating_sub(0x100)..ep_file_offset].to_vec();
    let mut xor_key = steam_xor(&mut header_bytes, 0);
    let mut fields = header_parser(&header_bytes)?;

    let mut tls_as_oep = false;
    let mut tls_oep_rva = 0u32;

    if fields.signature != 0xC0DEC0DF && fields.signature != 0xC0DEC0DE {
        if pe32.tls_callbacks.is_empty() {
            return Err(format!("Invalid SteamStub DRM header signature: 0x{:08X}", fields.signature));
        }

        let tls_rva = pe32.get_rva_from_va(pe32.tls_callbacks[0]);
        let tls_offset = pe32.get_file_offset_from_rva(tls_rva)?;
        header_bytes = pe32.raw_data[tls_offset.saturating_sub(0x100)..tls_offset].to_vec();
        xor_key = steam_xor(&mut header_bytes, 0);
        fields = header_parser(&header_bytes)?;

        if fields.signature != 0xC0DEC0DF && fields.signature != 0xC0DEC0DE {
            return Err(format!("Invalid SteamStub DRM header signature (TLS fallback): 0x{:08X}", fields.signature));
        }

        tls_as_oep = true;
        tls_oep_rva = tls_rva;
    }

    println!("[{}] Header validated successfully.", plugin_name);
    println!("  Original Entry Point: 0x{:08X}", fields.original_entry_point);
    println!("  Steam AppID:          {}", fields.steam_app_id);

    let oep_base_rva = if tls_as_oep { tls_oep_rva } else { pe32.entry_point };
    let payload_rva = oep_base_rva.saturating_sub(fields.bind_section_offset);
    let payload_size = (fields.payload_size + 0x0F) & !0x0F;

    if payload_size > 0 {
        if let Ok(payload_offset) = pe32.get_file_offset_from_rva(payload_rva) {
            if payload_offset + payload_size as usize <= pe32.raw_data.len() {
                let mut payload = pe32.raw_data[payload_offset..payload_offset + payload_size as usize].to_vec();
                steam_xor(&mut payload, xor_key);
            }
        }
    }

    if fields.drmp_dll_size > 0 {
        let drmp_rva = payload_rva + fields.drmp_dll_offset;
        if let Ok(drmp_offset) = pe32.get_file_offset_from_rva(drmp_rva) {
            if drmp_offset + fields.drmp_dll_size as usize <= pe32.raw_data.len() {
                let mut drmp_data = pe32.raw_data[drmp_offset..drmp_offset + fields.drmp_dll_size as usize].to_vec();
                steam_drmp_decrypt_pass1(&mut drmp_data, &fields.encryption_keys);
            }
        }
    }

    let mut decrypted_code: Option<Vec<u8>> = None;
    let mut code_sec_idx: Option<usize> = None;

    let no_encryption = (fields.flags & 1) != 0;
    if !no_encryption {
        if let Some(idx) = pe32.get_owner_section_index(fields.code_section_virtual_address as u32) {
            code_sec_idx = Some(idx);
            let sec = &pe32.sections[idx];
            let raw_size = sec.header.size_of_raw_data as usize;

            if raw_size > 0 {
                let stolen_data = fields.code_section_stolen_data;
                let stolen_len = stolen_data.len();
                let sec_file_offset = pe32.get_file_offset_from_rva(sec.header.virtual_address)?;

                let mut code_data = vec![0u8; raw_size + stolen_len];
                code_data[..stolen_len].copy_from_slice(&stolen_data);
                let sec_end = (sec_file_offset + raw_size).min(pe32.raw_data.len());
                let copy_size = sec_end.saturating_sub(sec_file_offset);
                code_data[stolen_len..stolen_len + copy_size].copy_from_slice(&pe32.raw_data[sec_file_offset..sec_file_offset + copy_size]);

                let mut aes = AesHelper::new(&fields.aes_key, &fields.aes_iv, CipherMode::CBC);
                aes.rebuild_iv(&fields.aes_iv);

                let decrypted = aes.decrypt(&code_data, CipherMode::CBC);
                decrypted_code = Some(decrypted[..raw_size].to_vec());
            }
        }
    }

    let new_entry_point = pe32.get_rva_from_va(fields.original_entry_point as u32);
    pe32.save_unpacked(output_path, new_entry_point, code_sec_idx, decrypted_code.as_deref(), true)?;

    Ok(())
}

/// SteamStub Variant 3.0 (x86) Unpacker Plugin.
pub struct Variant30x86;

impl UnpackerPlugin for Variant30x86 {
    fn name(&self) -> &'static str { "SteamStub Variant 3.0 Unpacker (x86)" }
    fn version(&self) -> &'static str { "3.0.0" }
    fn is_64bit(&self) -> bool { false }

    fn can_process(&self, pe: &PeFile) -> bool {
        if pe.is_64bit() || !pe.has_section(".bind") { return false; }
        if let PeFile::Pe32(pe32) = pe {
            if let Some(bind) = pe32.get_section(".bind") {
                if find_pattern(&bind.data, "E8 00 00 00 00 50 53 51 52 56 57 55 8B 44 24 1C 2D 05 00 00 00 8B CC 83 E4 F0 51 51 51 50").is_none() {
                    return false;
                }
                if let Some(off) = find_pattern(&bind.data, "55 8B EC 81 EC ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? 8D") {
                    if off + 20 <= bind.data.len() {
                        let header_size = i32::from_le_bytes(bind.data[off + 16..off + 20].try_into().unwrap()).abs();
                        return header_size == 0xB0 || header_size == 0xD0;
                    }
                }
            }
        }
        false
    }

    fn unpack(&self, pe: &PeFile, output_path: &str) -> Result<(), String> {
        let pe32 = match pe { PeFile::Pe32(f) => f, _ => return Err("Not a 32-bit PE file".into()) };
        unpack_v3_32(pe32, output_path, "SteamStub v3.0 x86", |data| {
            if data.len() < 0xB0 { return Err("Data too small for SteamStub32Var30Header".into()); }
            let h = SteamStub32Var30Header::parse(&data[data.len() - 0xB0..])?;
            Ok(V3HeaderFields {
                header_size: 0xB0, signature: h.signature, original_entry_point: h.original_entry_point as u64,
                bind_section_offset: h.bind_section_offset, payload_size: h.payload_size, drmp_dll_offset: h.drmp_dll_offset,
                drmp_dll_size: h.drmp_dll_size, steam_app_id: h.steam_app_id, flags: h.flags,
                code_section_virtual_address: h.code_section_virtual_address as u64, aes_key: h.aes_key, aes_iv: h.aes_iv,
                code_section_stolen_data: h.code_section_stolen_data, encryption_keys: h.encryption_keys,
            })
        })
    }
}

/// SteamStub Variant 3.0 (x64) Unpacker Plugin.
pub struct Variant30x64;

impl UnpackerPlugin for Variant30x64 {
    fn name(&self) -> &'static str { "SteamStub Variant 3.0 Unpacker (x64)" }
    fn version(&self) -> &'static str { "3.0.0" }
    fn is_64bit(&self) -> bool { true }

    fn can_process(&self, pe: &PeFile) -> bool {
        if !pe.is_64bit() || !pe.has_section(".bind") { return false; }
        if let PeFile::Pe64(pe64) = pe {
            if let Some(bind) = pe64.get_section(".bind") {
                if find_pattern(&bind.data, "E8 00 00 00 00 50 53 51 52 56 57 55 41 50").is_none() { return false; }
                if let Some(off) = find_pattern(&bind.data, "48 8D 91 ?? ?? ?? ?? 48") {
                    if off + 7 <= bind.data.len() {
                        let header_size = i32::from_le_bytes(bind.data[off + 3..off + 7].try_into().unwrap()).abs();
                        return header_size == 0xB0 || header_size == 0xD0;
                    }
                }
            }
        }
        false
    }

    fn unpack(&self, pe: &PeFile, output_path: &str) -> Result<(), String> {
        let pe64 = match pe { PeFile::Pe64(f) => f, _ => return Err("Not a 64-bit PE file".into()) };
        unpack_v3_64(pe64, output_path, "SteamStub v3.0 x64", |data| {
            if data.len() < 0xD0 { return Err("Data too small for SteamStub64Var30Header".into()); }
            let h = SteamStub64Var30Header::parse(&data[data.len() - 0xD0..])?;
            Ok(V3HeaderFields {
                header_size: 0xD0, signature: h.signature, original_entry_point: h.original_entry_point,
                bind_section_offset: h.bind_section_offset, payload_size: h.payload_size, drmp_dll_offset: h.drmp_dll_offset,
                drmp_dll_size: h.drmp_dll_size, steam_app_id: h.steam_app_id, flags: h.flags,
                code_section_virtual_address: h.code_section_virtual_address, aes_key: h.aes_key, aes_iv: h.aes_iv,
                code_section_stolen_data: h.code_section_stolen_data, encryption_keys: h.encryption_keys,
            })
        })
    }
}

/// SteamStub Variant 3.1 (x86) Unpacker Plugin.
pub struct Variant31x86;

impl UnpackerPlugin for Variant31x86 {
    fn name(&self) -> &'static str { "SteamStub Variant 3.1 Unpacker (x86)" }
    fn version(&self) -> &'static str { "3.1.0" }
    fn is_64bit(&self) -> bool { false }

    fn can_process(&self, pe: &PeFile) -> bool {
        if pe.is_64bit() || !pe.has_section(".bind") { return false; }
        if let PeFile::Pe32(pe32) = pe {
            if let Some(bind) = pe32.get_section(".bind") {
                if find_pattern(&bind.data, "E8 00 00 00 00 50 53 51 52 56 57 55 8B 44 24 1C 2D 05 00 00 00 8B CC 83 E4 F0 51 51 51 50").is_none() {
                    return false;
                }
                let variant_patterns: [(&str, usize); 3] = [
                    ("55 8B EC 81 EC ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? 68", 0x10),
                    ("55 8B EC 81 EC ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? 8D 83", 0x16),
                    ("55 8B EC 81 EC ?? ?? ?? ?? 56 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D", 0x10),
                ];
                for (pat, offset_val) in variant_patterns {
                    if let Some(off) = find_pattern(&bind.data, pat) {
                        if off + offset_val + 4 <= bind.data.len() {
                            let header_size = i32::from_le_bytes(bind.data[off + offset_val..off + offset_val + 4].try_into().unwrap()).abs();
                            if header_size == 0xF0 || header_size == 0xE8 || header_size == 0xEC {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn unpack(&self, pe: &PeFile, output_path: &str) -> Result<(), String> {
        let pe32 = match pe { PeFile::Pe32(f) => f, _ => return Err("Not a 32-bit PE file".into()) };
        unpack_v3_32(pe32, output_path, "SteamStub v3.1 x86", |data| {
            if data.len() < 0xE8 { return Err("Data too small for SteamStub32Var31Header".into()); }
            let h = SteamStub32Var31Header::parse(&data[data.len() - 0xE8..])?;
            Ok(V3HeaderFields {
                header_size: 0xE8, signature: h.signature, original_entry_point: h.original_entry_point as u64,
                bind_section_offset: h.bind_section_offset, payload_size: h.payload_size, drmp_dll_offset: h.drmp_dll_offset,
                drmp_dll_size: h.drmp_dll_size, steam_app_id: h.steam_app_id, flags: h.flags,
                code_section_virtual_address: h.code_section_virtual_address as u64, aes_key: h.aes_key, aes_iv: h.aes_iv,
                code_section_stolen_data: h.code_section_stolen_data, encryption_keys: h.encryption_keys,
            })
        })
    }
}

/// SteamStub Variant 3.1 (x64) Unpacker Plugin.
pub struct Variant31x64;

impl UnpackerPlugin for Variant31x64 {
    fn name(&self) -> &'static str { "SteamStub Variant 3.1 Unpacker (x64)" }
    fn version(&self) -> &'static str { "3.1.0" }
    fn is_64bit(&self) -> bool { true }

    fn can_process(&self, pe: &PeFile) -> bool {
        if !pe.is_64bit() || !pe.has_section(".bind") { return false; }
        if let PeFile::Pe64(pe64) = pe {
            if let Some(bind) = pe64.get_section(".bind") {
                if find_pattern(&bind.data, "E8 00 00 00 00 50 53 51 52 56 57 55 41 50").is_none() { return false; }
                let mut offset = find_pattern(&bind.data, "48 8D 91 ?? ?? ?? ?? 48");
                if offset.is_none() { offset = find_pattern(&bind.data, "48 8D 91 ?? ?? ?? ?? 41"); }
                if offset.is_none() {
                    if let Some(off2) = find_pattern(&bind.data, "48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48") {
                        offset = Some(off2 + 5);
                    }
                }
                if let Some(off) = offset {
                    if off + 7 <= bind.data.len() {
                        let header_size = i32::from_le_bytes(bind.data[off + 3..off + 7].try_into().unwrap()).abs();
                        return header_size == 0xF0 || header_size == 0xE8 || header_size == 0xEC;
                    }
                }
            }
        }
        false
    }

    fn unpack(&self, pe: &PeFile, output_path: &str) -> Result<(), String> {
        let pe64 = match pe { PeFile::Pe64(f) => f, _ => return Err("Not a 64-bit PE file".into()) };
        unpack_v3_64(pe64, output_path, "SteamStub v3.1 x64", |data| {
            if data.len() < 0xF0 { return Err("Data too small for SteamStub64Var31Header".into()); }
            let h = SteamStub64Var31Header::parse(&data[data.len() - 0xF0..])?;
            Ok(V3HeaderFields {
                header_size: 0xF0, signature: h.signature, original_entry_point: h.original_entry_point,
                bind_section_offset: h.bind_section_offset, payload_size: h.payload_size, drmp_dll_offset: h.drmp_dll_offset,
                drmp_dll_size: h.drmp_dll_size, steam_app_id: h.steam_app_id, flags: h.flags,
                code_section_virtual_address: h.code_section_virtual_address, aes_key: h.aes_key, aes_iv: h.aes_iv,
                code_section_stolen_data: h.code_section_stolen_data, encryption_keys: h.encryption_keys,
            })
        })
    }
}
