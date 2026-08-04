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

/// Helper function to compute and update the PE checksum in out_data.
pub fn compute_pe_checksum(out_data: &mut [u8], checksum_offset: usize) {
    if checksum_offset + 4 <= out_data.len() {
        out_data[checksum_offset..checksum_offset + 4].fill(0);

        let mut checksum: u64 = 0;
        let mut i = 0;
        while i + 1 < out_data.len() {
            let val = u16::from_le_bytes([out_data[i], out_data[i + 1]]) as u64;
            checksum = (checksum + val) + (checksum >> 32);
            checksum &= 0xFFFFFFFF;
            i += 2;
        }
        if i < out_data.len() {
            let val = out_data[i] as u64;
            checksum = (checksum + val) + (checksum >> 32);
            checksum &= 0xFFFFFFFF;
        }

        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum += checksum >> 16;
        checksum &= 0xFFFF;
        checksum += out_data.len() as u64;

        let csum_bytes = (checksum as u32).to_le_bytes();
        out_data[checksum_offset..checksum_offset + 4].copy_from_slice(&csum_bytes);
    }
}

/// Helper function to strip a section header (e.g. .bind) and zero out its raw data in out_data.
pub fn strip_section_header(
    out_data: &mut [u8],
    file_header_offset: usize,
    section_header_offset: usize,
    total_sections: usize,
    target_idx: usize,
    sec_hdr_size: usize,
    raw_ptr: usize,
    raw_size: usize,
) {
    // Decrease NumberOfSections in FileHeader (+2)
    let num_sections = u16::from_le_bytes(out_data[file_header_offset + 2..file_header_offset + 4].try_into().unwrap());
    if num_sections > 0 {
        let new_num = num_sections - 1;
        out_data[file_header_offset + 2..file_header_offset + 4].copy_from_slice(&new_num.to_le_bytes());
    }

    // Shift remaining section headers left
    let bind_hdr_offset = section_header_offset + target_idx * sec_hdr_size;
    let remaining_bytes = (total_sections - target_idx - 1) * sec_hdr_size;
    if remaining_bytes > 0 && bind_hdr_offset + sec_hdr_size + remaining_bytes <= out_data.len() {
        out_data.copy_within(
            bind_hdr_offset + sec_hdr_size..bind_hdr_offset + sec_hdr_size + remaining_bytes,
            bind_hdr_offset,
        );
    }

    // Zero out last section header slot
    let last_hdr_offset = section_header_offset + (total_sections - 1) * sec_hdr_size;
    if last_hdr_offset + sec_hdr_size <= out_data.len() {
        out_data[last_hdr_offset..last_hdr_offset + sec_hdr_size].fill(0);
    }

    // Zero out raw data of stripped section
    if raw_ptr + raw_size <= out_data.len() {
        out_data[raw_ptr..raw_ptr + raw_size].fill(0);
    }
}
