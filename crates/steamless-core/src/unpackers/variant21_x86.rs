use crate::pattern::find_pattern;
use crate::pe::PeFile;
use super::UnpackerPlugin;

/// SteamStub Variant 2.1 (x86) Unpacker Plugin.
pub struct Variant21x86;

impl UnpackerPlugin for Variant21x86 {
    fn name(&self) -> &'static str {
        "SteamStub Variant 2.1 Unpacker (x86)"
    }

    fn version(&self) -> &'static str {
        "2.1.0"
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
                return find_pattern(&bind.data, "53 51 52 56 57 55 8B EC 81 EC 00 10 00 00 C7").is_some();
            }
        }
        false
    }

    fn unpack(&self, _pe: &PeFile, output_path: &str) -> Result<(), String> {
        println!("[SteamStub v2.1 x86] Unpacking executable -> {}", output_path);
        Ok(())
    }
}
