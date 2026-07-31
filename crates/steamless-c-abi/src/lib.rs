use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::OnceLock;

use steamless_core::pe::PeFile;
use steamless_core::unpackers::UnpackerRegistry;

static REGISTRY: OnceLock<UnpackerRegistry> = OnceLock::new();

fn get_registry() -> &'static UnpackerRegistry {
    REGISTRY.get_or_init(UnpackerRegistry::new)
}

/// Checks if an executable file at `file_path` is protected by SteamStub DRM and can be processed.
///
/// # Returns
/// - `1` if the file can be unpacked.
/// - `0` if the file is clean or unsupported.
/// - `-1` if the file path is invalid or unreadable.
#[no_mangle]
pub extern "C" fn steamless_can_process(file_path: *const c_char) -> c_int {
    if file_path.is_null() {
        return -1;
    }

    let c_str = unsafe { CStr::from_ptr(file_path) };
    let path = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let data = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };

    let pe = match PeFile::parse(&data) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    let reg = get_registry();
    if reg.find_unpacker(&pe).is_some() {
        1
    } else {
        0
    }
}

/// Gets the matching SteamStub variant name for `file_path`.
///
/// # Returns
/// - Raw `*mut c_char` pointer to null-terminated string (must be freed with `steamless_free_string`).
/// - Null pointer if unsupported or invalid file.
#[no_mangle]
pub extern "C" fn steamless_get_variant(file_path: *const c_char) -> *mut c_char {
    if file_path.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(file_path) };
    let path = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let data = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    let pe = match PeFile::parse(&data) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };

    let reg = get_registry();
    if let Some(unpacker) = reg.find_unpacker(&pe) {
        let res = CString::new(unpacker.name()).unwrap();
        res.into_raw()
    } else {
        std::ptr::null_mut()
    }
}

/// Unpacks SteamStub DRM from `input_path` and writes the clean executable to `output_path`.
///
/// # Returns
/// - `0` on success.
/// - Non-zero error code on failure.
#[no_mangle]
pub extern "C" fn steamless_unpack(input_path: *const c_char, output_path: *const c_char) -> c_int {
    if input_path.is_null() || output_path.is_null() {
        return 1;
    }

    let in_str = match unsafe { CStr::from_ptr(input_path) }.to_str() {
        Ok(s) => s,
        Err(_) => return 1,
    };

    let out_str = match unsafe { CStr::from_ptr(output_path) }.to_str() {
        Ok(s) => s,
        Err(_) => return 2,
    };

    let data = match std::fs::read(in_str) {
        Ok(bytes) => bytes,
        Err(_) => return 3,
    };

    let pe = match PeFile::parse(&data) {
        Ok(p) => p,
        Err(_) => return 4,
    };

    let reg = get_registry();
    if let Some(unpacker) = reg.find_unpacker(&pe) {
        match unpacker.unpack(&pe, out_str) {
            Ok(_) => 0,
            Err(_) => 5,
        }
    } else {
        6
    }
}

/// Frees a string pointer allocated by `steamless_get_variant`.
#[no_mangle]
pub extern "C" fn steamless_free_string(ptr: *mut c_void) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr as *mut c_char);
        }
    }
}
