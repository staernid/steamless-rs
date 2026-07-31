pub mod file32;
pub mod file64;

pub use file32::{ImageDosHeader32, ImageFileHeader32, ImageSectionHeader32, Pe32File, Pe32Section};
pub use file64::{ImageDosHeader64, ImageFileHeader64, ImageSectionHeader64, Pe64File, Pe64Section};

#[derive(Debug, Clone)]
pub enum PeFile {
    Pe32(Pe32File),
    Pe64(Pe64File),
}

impl PeFile {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if let Ok(pe32) = Pe32File::parse(data) {
            return Ok(PeFile::Pe32(pe32));
        }
        if let Ok(pe64) = Pe64File::parse(data) {
            return Ok(PeFile::Pe64(pe64));
        }
        Err("Failed to parse file as PE32 or PE32+".into())
    }

    pub fn is_64bit(&self) -> bool {
        matches!(self, PeFile::Pe64(_))
    }

    pub fn has_section(&self, name: &str) -> bool {
        match self {
            PeFile::Pe32(f) => f.has_section(name),
            PeFile::Pe64(f) => f.has_section(name),
        }
    }

    pub fn entry_point(&self) -> u32 {
        match self {
            PeFile::Pe32(f) => f.entry_point,
            PeFile::Pe64(f) => f.entry_point,
        }
    }

    pub fn image_base(&self) -> u64 {
        match self {
            PeFile::Pe32(f) => f.image_base as u64,
            PeFile::Pe64(f) => f.image_base,
        }
    }
}
