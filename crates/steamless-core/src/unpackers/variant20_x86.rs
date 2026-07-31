use crate::pattern::find_pattern;
use crate::pe::PeFile;
use super::UnpackerPlugin;

/// SteamStub Variant 2.0 (x86) Unpacker Plugin.
pub struct Variant20x86;

impl UnpackerPlugin for Variant20x86 {
    fn name(&self) -> &'static str {
        "SteamStub Variant 2.0 Unpacker (x86)"
    }

    fn version(&self) -> &'static str {
        "2.0.0"
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
                return find_pattern(&bind.data, "8B 44 24 04 8B 4C 24 08 8B 54 24 0C").is_some();
            }
        }
        false
    }

    fn unpack(&self, _pe: &PeFile, output_path: &str) -> Result<(), String> {
        println!("[SteamStub v2.0 x86] Unpacking executable -> {}", output_path);
        Ok(())
    }
}
