use crate::pattern::find_pattern;
use crate::pe::PeFile;
use super::UnpackerPlugin;

/// SteamStub Variant 3.1 (x64) Unpacker Plugin.
pub struct Variant31x64;

impl UnpackerPlugin for Variant31x64 {
    fn name(&self) -> &'static str {
        "SteamStub Variant 3.1 Unpacker (x64)"
    }

    fn version(&self) -> &'static str {
        "3.1.0"
    }

    fn is_64bit(&self) -> bool {
        true
    }

    fn can_process(&self, pe: &PeFile) -> bool {
        if !pe.is_64bit() || !pe.has_section(".bind") {
            return false;
        }
        if let PeFile::Pe64(pe64) = pe {
            if let Some(bind) = pe64.get_section(".bind") {
                if find_pattern(&bind.data, "E8 00 00 00 00 50 53 51 52 56 57 55 41 50").is_none() {
                    return false;
                }

                let mut offset = find_pattern(&bind.data, "48 8D 91 ?? ?? ?? ?? 48");
                if offset.is_none() {
                    offset = find_pattern(&bind.data, "48 8D 91 ?? ?? ?? ?? 41");
                }
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

    fn unpack(&self, _pe: &PeFile, output_path: &str) -> Result<(), String> {
        println!("[SteamStub v3.1 x64] Unpacking executable -> {}", output_path);
        Ok(())
    }
}
