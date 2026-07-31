#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct ImageDosHeader32 {
    pub e_magic: u16,    // "MZ"
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,   // PE NT Header Offset
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct ImageFileHeader32 {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct ImageSectionHeader32 {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct Pe32Section {
    pub header: ImageSectionHeader32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Pe32File {
    pub dos_header: ImageDosHeader32,
    pub file_header: ImageFileHeader32,
    pub entry_point: u32,
    pub image_base: u32,
    pub base_of_code: u32,
    pub sections: Vec<Pe32Section>,
    pub raw_data: Vec<u8>,
}

impl Pe32File {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < std::mem::size_of::<ImageDosHeader32>() {
            return Err("File too small for DOS header".into());
        }

        let dos_header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const ImageDosHeader32) };
        if dos_header.e_magic != 0x5A4D {
            return Err("Invalid DOS signature".into());
        }

        let lfanew = dos_header.e_lfanew as usize;
        if lfanew + 4 > data.len() {
            return Err("Invalid e_lfanew offset".into());
        }

        let pe_sig = u32::from_le_bytes(data[lfanew..lfanew + 4].try_into().unwrap());
        if pe_sig != 0x00004550 {
            return Err("Invalid PE signature".into());
        }

        let file_header_offset = lfanew + 4;
        let file_header = unsafe {
            std::ptr::read_unaligned(data[file_header_offset..].as_ptr() as *const ImageFileHeader32)
        };

        let opt_header_offset = file_header_offset + std::mem::size_of::<ImageFileHeader32>();
        let magic = u16::from_le_bytes(data[opt_header_offset..opt_header_offset + 2].try_into().unwrap());
        if magic != 0x010B {
            return Err("Not a PE32 32-bit executable".into());
        }

        let entry_point = u32::from_le_bytes(data[opt_header_offset + 16..opt_header_offset + 20].try_into().unwrap());
        let base_of_code = u32::from_le_bytes(data[opt_header_offset + 20..opt_header_offset + 24].try_into().unwrap());
        let image_base = u32::from_le_bytes(data[opt_header_offset + 28..opt_header_offset + 32].try_into().unwrap());

        let section_header_offset = opt_header_offset + file_header.size_of_optional_header as usize;
        let mut sections = Vec::new();

        for i in 0..file_header.number_of_sections as usize {
            let offset = section_header_offset + i * std::mem::size_of::<ImageSectionHeader32>();
            if offset + std::mem::size_of::<ImageSectionHeader32>() > data.len() {
                break;
            }

            let sec_header = unsafe {
                std::ptr::read_unaligned(data[offset..].as_ptr() as *const ImageSectionHeader32)
            };

            let raw_ptr = sec_header.pointer_to_raw_data as usize;
            let raw_size = sec_header.size_of_raw_data as usize;

            let sec_data = if raw_ptr + raw_size <= data.len() {
                data[raw_ptr..raw_ptr + raw_size].to_vec()
            } else if raw_ptr < data.len() {
                data[raw_ptr..].to_vec()
            } else {
                Vec::new()
            };

            sections.push(Pe32Section {
                header: sec_header,
                data: sec_data,
            });
        }

        Ok(Pe32File {
            dos_header,
            file_header,
            entry_point,
            image_base,
            base_of_code,
            sections,
            raw_data: data.to_vec(),
        })
    }

    pub fn has_section(&self, name: &str) -> bool {
        self.get_section(name).is_some()
    }

    pub fn get_section(&self, name: &str) -> Option<&Pe32Section> {
        self.sections.iter().find(|s| {
            let sec_name = String::from_utf8_lossy(&s.header.name);
            sec_name.trim_matches('\0') == name
        })
    }
}
