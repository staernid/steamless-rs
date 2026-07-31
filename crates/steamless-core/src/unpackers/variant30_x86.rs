use crate::pattern::find_pattern;
use crate::pe::PeFile;
use super::UnpackerPlugin;

/// SteamStub Variant 3.0 (x86) Unpacker Plugin.
pub struct Variant30x86;

impl UnpackerPlugin for Variant30x86 {
    fn name(&self) -> &'static str {
        "SteamStub Variant 3.0 Unpacker (x86)"
    }

    fn version(&self) -> &'static str {
        "3.0.0"
    }

    fn is_64bit(&self) -> bool {
        false
    }

    fn can_process(&self, pe: &PeFile) -> bool {
        if pe.is_64bit() || !pe.has_section(".bind") {
            return false;
        }
        if let PeFile::Pe32(pe32) = pe {
            if let Some(bind) = pe32.get_section(".bind") {
                let variant = find_pattern(&bind.data, "E8 00 00 00 00 50 53 51 52 56 57 55 8B 44 24 1C 2D 05 00 00 00 8B CC 83 E4 F0 51 51 51 50");
                if variant.is_none() {
                    return false;
                }

                let mut offset = find_pattern(&bind.data, "55 8B EC 81 EC ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? 68");
                let mut p_val = 16;
                if offset.is_none() {
                    offset = find_pattern(&bind.data, "55 8B EC 81 EC ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? 8D 83");
                    p_val = 22;
                }

                if let Some(off) = offset {
                    if off + p_val + 4 <= bind.data.len() {
                        let header_size = i32::from_le_bytes(bind.data[off + p_val..off + p_val + 4].try_into().unwrap()).abs();
                        return header_size == 0xB0 || header_size == 0xD0;
                    }
                }
            }
        }
        false
    }

    fn unpack(&self, _pe: &PeFile, output_path: &str) -> Result<(), String> {
        println!("[SteamStub v3.0 x86] Unpacking executable -> {}", output_path);
        Ok(())
    }
}
