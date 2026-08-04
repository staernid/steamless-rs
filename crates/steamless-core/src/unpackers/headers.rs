/// SteamStub DRM Variant 1.0 x86 Header structure (0x2C bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SteamStub32Var10Header {
    pub xor_key: u32,
    pub signature: u32,
    pub image_base: u32,
    pub address_of_entry_point: u32,
    pub bind_section_offset: u32,
    pub original_entry_point: u32,
    pub payload_size: u32,
    pub drmp_dll_offset: u32,
    pub drmp_dll_size: u32,
    pub steam_app_id: u32,
    pub flags: u32,
}

impl SteamStub32Var10Header {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < std::mem::size_of::<Self>() {
            return Err("Data too small for SteamStub32Var10Header".into());
        }
        let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) };
        Ok(header)
    }
}

/// SteamStub DRM Variant 2.0 x86 Header structure (856 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SteamStub32Var20_856_Header {
    pub xor_key1: u32,
    pub xor_key2: u32,
    pub get_module_handle_a_idata: u32,
    pub get_proc_address_idata: u32,
    pub get_module_handle_w_idata: u32,
    pub flags: u32,
    pub unknown0000: u32,
    pub bind_section_virtual_address: u32,
    pub bind_section_code_size: u32,
    pub bind_section_hash: u32,
    pub oep: u32,
    pub code_section_virtual_address: u32,
    pub code_section_size: u32,
    pub code_section_xor_key: u32,
    pub steam_app_id: u32,
    pub steam_app_id_string: [u8; 8],
    pub stub_data: [u8; 0x314],
}

impl SteamStub32Var20_856_Header {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < std::mem::size_of::<Self>() {
            return Err("Data too small for SteamStub32Var20_856_Header".into());
        }
        let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) };
        Ok(header)
    }
}

/// SteamStub DRM Variant 2.0 x86 Header structure (884 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SteamStub32Var20_884_Header {
    pub xor_key1: u32,
    pub xor_key2: u32,
    pub get_module_handle_a_idata: u32,
    pub get_proc_address_idata: u32,
    pub load_library_a_idata: u32,
    pub get_proc_address_custom: u32,
    pub flags: u32,
    pub unknown0000: u32,
    pub bind_section_virtual_address: u32,
    pub bind_section_code_size: u32,
    pub bind_section_hash: u32,
    pub oep: u32,
    pub code_section_virtual_address: u32,
    pub code_section_size: u32,
    pub code_section_xor_key: u32,
    pub steam_app_id: u32,
    pub steam_app_id_string: [u8; 8],
    pub stub_data: [u8; 0x32C],
}

impl SteamStub32Var20_884_Header {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < std::mem::size_of::<Self>() {
            return Err("Data too small for SteamStub32Var20_884_Header".into());
        }
        let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) };
        Ok(header)
    }
}

/// SteamStub DRM Variant 3.0 x86 Header structure (0xB0 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SteamStub32Var30Header {
    pub xor_key: u32,
    pub signature: u32,
    pub image_base: u64,
    pub address_of_entry_point: u32,
    pub bind_section_offset: u32,
    pub unknown0000: u32,
    pub original_entry_point: u32,
    pub unknown0001: u32,
    pub payload_size: u32,
    pub drmp_dll_offset: u32,
    pub drmp_dll_size: u32,
    pub steam_app_id: u32,
    pub flags: u32,
    pub bind_section_virtual_size: u32,
    pub unknown0002: u32,
    pub code_section_virtual_address: u32,
    pub code_section_raw_size: u32,
    pub aes_key: [u8; 32],
    pub aes_iv: [u8; 16],
    pub code_section_stolen_data: [u8; 16],
    pub encryption_keys: [u32; 4],
    pub unknown0003: [u32; 6],
    pub get_module_handle_a_rva: u32,
    pub get_module_handle_w_rva: u32,
    pub load_library_a_rva: u32,
    pub load_library_w_rva: u32,
    pub get_proc_address_rva: u32,
    pub unknown0009: [u32; 3],
}

impl SteamStub32Var30Header {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < std::mem::size_of::<Self>() {
            return Err("Data too small for SteamStub32Var30Header".into());
        }
        let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) };
        Ok(header)
    }
}

/// SteamStub DRM Variant 3.0 x64 Header structure (0xD0 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SteamStub64Var30Header {
    pub xor_key: u32,
    pub signature: u32,
    pub image_base: u64,
    pub address_of_entry_point: u64,
    pub bind_section_offset: u32,
    pub unknown0000: u32,
    pub original_entry_point: u64,
    pub unknown0001: u32,
    pub payload_size: u32,
    pub drmp_dll_offset: u32,
    pub drmp_dll_size: u32,
    pub steam_app_id: u32,
    pub flags: u32,
    pub bind_section_virtual_size: u32,
    pub unknown0002: u32,
    pub code_section_virtual_address: u64,
    pub code_section_raw_size: u64,
    pub aes_key: [u8; 32],
    pub aes_iv: [u8; 16],
    pub code_section_stolen_data: [u8; 16],
    pub encryption_keys: [u32; 4],
    pub unknown0003: [u32; 6],
    pub get_module_handle_a_rva: u64,
    pub get_module_handle_w_rva: u64,
    pub load_library_a_rva: u64,
    pub load_library_w_rva: u64,
    pub get_proc_address_rva: u64,
    pub unknown0009: [u32; 3],
}

impl SteamStub64Var30Header {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < std::mem::size_of::<Self>() {
            return Err("Data too small for SteamStub64Var30Header".into());
        }
        let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) };
        Ok(header)
    }
}

/// SteamStub DRM Variant 3.1 x86 Header structure (0xE8 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SteamStub32Var31Header {
    pub xor_key: u32,
    pub signature: u32,
    pub image_base: u64,
    pub address_of_entry_point: u32,
    pub bind_section_offset: u32,
    pub unknown0000: u32,
    pub original_entry_point: u32,
    pub unknown0001: u32,
    pub payload_size: u32,
    pub drmp_dll_offset: u32,
    pub drmp_dll_size: u32,
    pub steam_app_id: u32,
    pub flags: u32,
    pub bind_section_virtual_size: u32,
    pub unknown0002: u32,
    pub code_section_virtual_address: u32,
    pub code_section_raw_size: u32,
    pub aes_key: [u8; 32],
    pub aes_iv: [u8; 16],
    pub code_section_stolen_data: [u8; 16],
    pub encryption_keys: [u32; 4],
    pub unknown0003: [u32; 8],
    pub get_module_handle_a_rva: u32,
    pub get_module_handle_w_rva: u32,
    pub load_library_a_rva: u32,
    pub load_library_w_rva: u32,
    pub get_proc_address_rva: u32,
}

impl SteamStub32Var31Header {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < std::mem::size_of::<Self>() {
            return Err("Data too small for SteamStub32Var31Header".into());
        }
        let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) };
        Ok(header)
    }
}

/// SteamStub DRM Variant 3.1 x64 Header structure (0xF0 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SteamStub64Var31Header {
    pub xor_key: u32,
    pub signature: u32,
    pub image_base: u64,
    pub address_of_entry_point: u64,
    pub bind_section_offset: u32,
    pub unknown0000: u32,
    pub original_entry_point: u64,
    pub unknown0001: u32,
    pub payload_size: u32,
    pub drmp_dll_offset: u32,
    pub drmp_dll_size: u32,
    pub steam_app_id: u32,
    pub flags: u32,
    pub bind_section_virtual_size: u32,
    pub unknown0002: u32,
    pub code_section_virtual_address: u64,
    pub code_section_raw_size: u64,
    pub aes_key: [u8; 32],
    pub aes_iv: [u8; 16],
    pub code_section_stolen_data: [u8; 16],
    pub encryption_keys: [u32; 4],
    pub unknown0003: [u32; 8],
    pub get_module_handle_a_rva: u64,
    pub get_module_handle_w_rva: u64,
    pub load_library_a_rva: u64,
    pub load_library_w_rva: u64,
    pub get_proc_address_rva: u64,
}

impl SteamStub64Var31Header {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < std::mem::size_of::<Self>() {
            return Err("Data too small for SteamStub64Var31Header".into());
        }
        let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Self) };
        Ok(header)
    }
}
