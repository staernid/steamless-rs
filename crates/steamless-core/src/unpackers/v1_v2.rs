use crate::crypto::{steam_drmp_decrypt_pass1, steam_xor};
use crate::pattern::find_pattern;
use crate::pe::PeFile;
use super::headers::{SteamStub32Var10Header, SteamStub32Var20_856_Header, SteamStub32Var20_884_Header};
use super::UnpackerPlugin;

/// SteamStub Variant 1.0 (x86) Unpacker Plugin.
pub struct Variant10x86;

impl UnpackerPlugin for Variant10x86 {
    fn name(&self) -> &'static str { "SteamStub Variant 1.0 Unpacker (x86)" }
    fn version(&self) -> &'static str { "1.0.0" }
    fn is_64bit(&self) -> bool { false }

    fn can_process(&self, pe: &PeFile) -> bool {
        if pe.is_64bit() || !pe.has_section(".bind") { return false; }
        if let PeFile::Pe32(pe32) = pe {
            if let Some(bind) = pe32.get_section(".bind") {
                return find_pattern(&bind.data, "60 81 EC 00 10 00 00 BE ?? ?? ?? ?? B9 6A").is_some();
            }
        }
        false
    }

    fn unpack(&self, pe: &PeFile, output_path: &str) -> Result<(), String> {
        let pe32 = match pe { PeFile::Pe32(f) => f, _ => return Err("Not a 32-bit PE file".into()) };
        let ep_file_offset = pe32.get_file_offset_from_rva(pe32.entry_point)?;
        if ep_file_offset < 0x2C {
            return Err("Entry point file offset too small for SteamStub v1.0 header".into());
        }

        let mut header_bytes = pe32.raw_data[ep_file_offset - 0x2C..ep_file_offset].to_vec();
        let xor_key = steam_xor(&mut header_bytes, 0);
        let stub_header = SteamStub32Var10Header::parse(&header_bytes)?;

        let sig = stub_header.signature;
        if sig != 0xC0DEC0DF {
            return Err(format!("Invalid SteamStub v1.0 header signature: 0x{:08X}", sig));
        }

        let oep = stub_header.original_entry_point;
        let app_id = stub_header.steam_app_id;
        println!("[SteamStub v1.0 x86] Header validated successfully.");
        println!("  Original Entry Point: 0x{:08X}", oep);
        println!("  Steam AppID:          {}", app_id);

        let bind_offset = stub_header.bind_section_offset;
        let payload_rva = pe32.entry_point.saturating_sub(bind_offset);
        let payload_sz = stub_header.payload_size;
        let payload_size = (payload_sz + 0x0F) & !0x0F;

        if payload_size > 0 {
            if let Ok(payload_offset) = pe32.get_file_offset_from_rva(payload_rva) {
                if payload_offset + payload_size as usize <= pe32.raw_data.len() {
                    let mut payload = pe32.raw_data[payload_offset..payload_offset + payload_size as usize].to_vec();
                    steam_xor(&mut payload, xor_key);
                }
            }
        }

        let drmp_size = stub_header.drmp_dll_size;
        let drmp_offset_val = stub_header.drmp_dll_offset;
        if drmp_size > 0 {
            let drmp_rva = payload_rva + drmp_offset_val;
            if let Ok(drmp_offset) = pe32.get_file_offset_from_rva(drmp_rva) {
                if drmp_offset + drmp_size as usize <= pe32.raw_data.len() {
                    let mut drmp_data = pe32.raw_data[drmp_offset..drmp_offset + drmp_size as usize].to_vec();
                    steam_drmp_decrypt_pass1(&mut drmp_data, &[0; 4]);
                }
            }
        }

        let new_entry_point = pe32.get_rva_from_va(oep);
        pe32.save_unpacked(output_path, new_entry_point, None, None, true)?;

        Ok(())
    }
}

/// SteamStub Variant 2.0 (x86) Unpacker Plugin.
pub struct Variant20x86;

impl UnpackerPlugin for Variant20x86 {
    fn name(&self) -> &'static str { "SteamStub Variant 2.0 Unpacker (x86)" }
    fn version(&self) -> &'static str { "2.0.0" }
    fn is_64bit(&self) -> bool { false }

    fn can_process(&self, pe: &PeFile) -> bool {
        if pe.is_64bit() || !pe.has_section(".bind") { return false; }
        if let PeFile::Pe32(pe32) = pe {
            if let Some(bind) = pe32.get_section(".bind") {
                return find_pattern(&bind.data, "55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 8B 7D 08").is_some();
            }
        }
        false
    }

    fn unpack(&self, pe: &PeFile, output_path: &str) -> Result<(), String> {
        let pe32 = match pe { PeFile::Pe32(f) => f, _ => return Err("Not a 32-bit PE file".into()) };
        let ep_file_offset = pe32.get_file_offset_from_rva(pe32.entry_point)?;
        if ep_file_offset < 856 {
            return Err("Entry point file offset too small for SteamStub v2.0 header".into());
        }

        let mut header_bytes = pe32.raw_data[ep_file_offset - 856..ep_file_offset].to_vec();
        let xor_key = steam_xor(&mut header_bytes, 0);
        let stub_header = SteamStub32Var20_856_Header::parse(&header_bytes)?;

        let oep = stub_header.oep;
        let app_id = stub_header.steam_app_id;
        println!("[SteamStub v2.0 x86] Header validated successfully.");
        println!("  Original Entry Point: 0x{:08X}", oep);
        println!("  Steam AppID:          {}", app_id);

        let mut decrypted_code: Option<Vec<u8>> = None;
        let mut code_sec_idx: Option<usize> = None;

        let code_sec_va = stub_header.code_section_virtual_address;
        if let Some(idx) = pe32.get_owner_section_index(code_sec_va) {
            code_sec_idx = Some(idx);
            let sec = &pe32.sections[idx];
            let raw_size = sec.header.size_of_raw_data as usize;
            if raw_size > 0 {
                let sec_file_offset = pe32.get_file_offset_from_rva(sec.header.virtual_address)?;
                let mut code_data = pe32.raw_data[sec_file_offset..sec_file_offset + raw_size].to_vec();
                let code_xor_key = stub_header.code_section_xor_key;
                if code_xor_key != 0 {
                    steam_xor(&mut code_data, code_xor_key);
                } else {
                    steam_xor(&mut code_data, xor_key);
                }
                decrypted_code = Some(code_data);
            }
        }

        let new_entry_point = pe32.get_rva_from_va(oep);
        pe32.save_unpacked(output_path, new_entry_point, code_sec_idx, decrypted_code.as_deref(), true)?;

        Ok(())
    }
}

/// SteamStub Variant 2.1 (x86) Unpacker Plugin.
pub struct Variant21x86;

impl UnpackerPlugin for Variant21x86 {
    fn name(&self) -> &'static str { "SteamStub Variant 2.1 Unpacker (x86)" }
    fn version(&self) -> &'static str { "2.1.0" }
    fn is_64bit(&self) -> bool { false }

    fn can_process(&self, pe: &PeFile) -> bool {
        if pe.is_64bit() || !pe.has_section(".bind") { return false; }
        if let PeFile::Pe32(pe32) = pe {
            if let Some(bind) = pe32.get_section(".bind") {
                return find_pattern(&bind.data, "55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 8D 7D").is_some();
            }
        }
        false
    }

    fn unpack(&self, pe: &PeFile, output_path: &str) -> Result<(), String> {
        let pe32 = match pe { PeFile::Pe32(f) => f, _ => return Err("Not a 32-bit PE file".into()) };
        let ep_file_offset = pe32.get_file_offset_from_rva(pe32.entry_point)?;
        if ep_file_offset < 884 {
            return Err("Entry point file offset too small for SteamStub v2.1 header".into());
        }

        let mut header_bytes = pe32.raw_data[ep_file_offset - 884..ep_file_offset].to_vec();
        let xor_key = steam_xor(&mut header_bytes, 0);
        let stub_header = SteamStub32Var20_884_Header::parse(&header_bytes)?;

        let oep = stub_header.oep;
        let app_id = stub_header.steam_app_id;
        println!("[SteamStub v2.1 x86] Header validated successfully.");
        println!("  Original Entry Point: 0x{:08X}", oep);
        println!("  Steam AppID:          {}", app_id);

        let mut decrypted_code: Option<Vec<u8>> = None;
        let mut code_sec_idx: Option<usize> = None;

        let code_sec_va = stub_header.code_section_virtual_address;
        if let Some(idx) = pe32.get_owner_section_index(code_sec_va) {
            code_sec_idx = Some(idx);
            let sec = &pe32.sections[idx];
            let raw_size = sec.header.size_of_raw_data as usize;
            if raw_size > 0 {
                let sec_file_offset = pe32.get_file_offset_from_rva(sec.header.virtual_address)?;
                let mut code_data = pe32.raw_data[sec_file_offset..sec_file_offset + raw_size].to_vec();
                let code_xor_key = stub_header.code_section_xor_key;
                if code_xor_key != 0 {
                    steam_xor(&mut code_data, code_xor_key);
                } else {
                    steam_xor(&mut code_data, xor_key);
                }
                decrypted_code = Some(code_data);
            }
        }

        let new_entry_point = pe32.get_rva_from_va(oep);
        pe32.save_unpacked(output_path, new_entry_point, code_sec_idx, decrypted_code.as_deref(), true)?;

        Ok(())
    }
}
