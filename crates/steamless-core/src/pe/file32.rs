use std::fs;
use super::{compute_pe_checksum, strip_section_header};

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
    pub tls_callbacks: Vec<u32>,
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

        // Parse TLS directory if present
        let mut tls_callbacks = Vec::new();
        let num_rva_sizes = u32::from_le_bytes(data[opt_header_offset + 92..opt_header_offset + 96].try_into().unwrap_or([0; 4]));
        if num_rva_sizes >= 10 {
            let tls_dir_rva = u32::from_le_bytes(data[opt_header_offset + 168..opt_header_offset + 172].try_into().unwrap_or([0; 4]));
            if tls_dir_rva > 0 {
                if let Ok(tls_offset) = Self::rva_to_file_offset_static(&sections, tls_dir_rva) {
                    if tls_offset + 24 <= data.len() {
                        let callbacks_va = u32::from_le_bytes(data[tls_offset + 12..tls_offset + 16].try_into().unwrap_or([0; 4]));
                        if callbacks_va > 0 {
                            let callbacks_rva = if callbacks_va >= image_base { callbacks_va - image_base } else { callbacks_va };
                            if let Ok(mut cb_offset) = Self::rva_to_file_offset_static(&sections, callbacks_rva) {
                                while cb_offset + 4 <= data.len() {
                                    let cb = u32::from_le_bytes(data[cb_offset..cb_offset + 4].try_into().unwrap_or([0; 4]));
                                    if cb == 0 { break; }
                                    tls_callbacks.push(cb);
                                    cb_offset += 4;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(Pe32File {
            dos_header,
            file_header,
            entry_point,
            image_base,
            base_of_code,
            sections,
            raw_data: data.to_vec(),
            tls_callbacks,
        })
    }

    fn rva_to_file_offset_static(sections: &[Pe32Section], rva: u32) -> Result<usize, String> {
        for s in sections {
            let v_addr = s.header.virtual_address;
            let v_size = s.header.virtual_size.max(s.header.size_of_raw_data);
            if rva >= v_addr && rva < v_addr + v_size {
                let offset_in_sec = rva - v_addr;
                return Ok(s.header.pointer_to_raw_data as usize + offset_in_sec as usize);
            }
        }
        Err(format!("RVA 0x{:08X} not found in any section", rva))
    }

    pub fn get_file_offset_from_rva(&self, rva: u32) -> Result<usize, String> {
        Self::rva_to_file_offset_static(&self.sections, rva)
    }

    pub fn get_rva_from_va(&self, va: u32) -> u32 {
        if va >= self.image_base {
            va - self.image_base
        } else {
            va
        }
    }

    pub fn get_owner_section_index(&self, va_or_rva: u32) -> Option<usize> {
        let rva = self.get_rva_from_va(va_or_rva);
        for (i, s) in self.sections.iter().enumerate() {
            let v_addr = s.header.virtual_address;
            let v_size = s.header.virtual_size.max(s.header.size_of_raw_data);
            if rva >= v_addr && rva < v_addr + v_size {
                return Some(i);
            }
        }
        None
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

    /// Rebuilds PE32 file bytes with new entry point, updated code section, removed .bind section, and updated PE checksum, writing to output_path.
    pub fn save_unpacked(
        &self,
        output_path: &str,
        new_entry_point: u32,
        code_sec_index: Option<usize>,
        new_code_data: Option<&[u8]>,
        remove_bind: bool,
    ) -> Result<(), String> {
        let mut out_data = self.raw_data.clone();

        let lfanew = self.dos_header.e_lfanew as usize;
        let file_header_offset = lfanew + 4;
        let opt_header_offset = file_header_offset + std::mem::size_of::<ImageFileHeader32>();
        let section_header_offset = opt_header_offset + self.file_header.size_of_optional_header as usize;

        // 1. Update AddressOfEntryPoint in Optional Header (offset +16)
        let ep_bytes = new_entry_point.to_le_bytes();
        out_data[opt_header_offset + 16..opt_header_offset + 20].copy_from_slice(&ep_bytes);

        // 2. If new code data is supplied, copy it into out_data at pointer_to_raw_data
        if let (Some(idx), Some(code_data)) = (code_sec_index, new_code_data) {
            if idx < self.sections.len() {
                let sec = &self.sections[idx];
                let ptr = sec.header.pointer_to_raw_data as usize;
                let copy_len = code_data.len().min(out_data.len().saturating_sub(ptr));
                if ptr + copy_len <= out_data.len() {
                    out_data[ptr..ptr + copy_len].copy_from_slice(&code_data[..copy_len]);
                }
            }
        }

        // 3. Remove .bind section if requested
        if remove_bind {
            let mut bind_index = None;
            for (i, s) in self.sections.iter().enumerate() {
                let name = String::from_utf8_lossy(&s.header.name);
                if name.trim_matches('\0') == ".bind" {
                    bind_index = Some(i);
                    break;
                }
            }

            if let Some(bind_idx) = bind_index {
                let bind_header = self.sections[bind_idx].header;
                strip_section_header(
                    &mut out_data,
                    file_header_offset,
                    section_header_offset,
                    self.sections.len(),
                    bind_idx,
                    std::mem::size_of::<ImageSectionHeader32>(),
                    bind_header.pointer_to_raw_data as usize,
                    bind_header.size_of_raw_data as usize,
                );
            }
        }

        // 4. Update CheckSum in Optional Header (offset +64)
        compute_pe_checksum(&mut out_data, opt_header_offset + 64);

        // Write output to file
        fs::write(output_path, &out_data).map_err(|e| format!("Failed to write unpacked executable: {}", e))
    }
}
