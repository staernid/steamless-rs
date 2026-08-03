use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use steamless_core::pe::PeFile;
use steamless_core::unpackers::UnpackerRegistry;

fn main() {
    let version = env!("STEAMLESS_VERSION");
    println!("Steamless Engine v{version} (Portable Native Rust Edition)");
    println!("{}", "=".repeat(50));

    let registry = UnpackerRegistry::new();
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("\nRegistered Unpacker Plugins:");
        for (name, version, is_64bit) in registry.list_plugins() {
            let arch = if is_64bit { "x64" } else { "x86" };
            println!("  - [{}] {} (v{})", arch, name, version);
        }
        println!("\nUsage: steamless <target_executable.exe | game_directory> [output_executable.exe]");
        return;
    }

    let input_path = Path::new(&args[1]);

    if input_path.is_dir() {
        process_directory(input_path, &registry);
    } else {
        let output_path = if args.len() > 2 {
            args[2].clone()
        } else {
            format!("{}.unpacked.exe", args[1])
        };
        if !process_file(input_path, &output_path, &registry) {
            std::process::exit(1);
        }
    }
}

fn process_file(input_path: &Path, output_path: &str, registry: &UnpackerRegistry) -> bool {
    println!("\nInspecting executable: {}", input_path.display());
    let data = match fs::read(input_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            return false;
        }
    };

    match PeFile::parse(&data) {
        Ok(pe) => {
            println!("  PE Architecture: {}", if pe.is_64bit() { "64-bit (PE32+)" } else { "32-bit (PE32)" });
            println!("  Entry Point RVA: 0x{:08X}", pe.entry_point());
            println!("  Image Base:      0x{:016X}", pe.image_base());

            if let Some(unpacker) = registry.find_unpacker(&pe) {
                println!("\n[MATCH FOUND] Protected by: {}", unpacker.name());
                match unpacker.unpack(&pe, output_path) {
                    Ok(_) => {
                        println!("[SUCCESS] Unpacked binary written to: {}", output_path);
                        true
                    }
                    Err(err) => {
                        eprintln!("[ERROR] Unpacking failed: {}", err);
                        false
                    }
                }
            } else {
                println!("\n[INFO] Executable is clean or uses an unsupported DRM variant.");
                true
            }
        }
        Err(err) => {
            eprintln!("Failed to parse PE headers: {}", err);
            false
        }
    }
}

fn process_directory(dir_path: &Path, registry: &UnpackerRegistry) {
    println!("\nScanning directory for SteamStub-protected executables: {}", dir_path.display());
    let mut exe_files = Vec::new();
    find_exe_files(dir_path, &mut exe_files);

    if exe_files.is_empty() {
        println!("[INFO] No executable (.exe) files found in directory.");
        return;
    }

    let mut unpacked_count = 0;
    for exe in exe_files {
        let path_str = exe.to_string_lossy();
        if path_str.contains(".unpacked") || path_str.contains(".ORIGINAL") {
            continue;
        }

        let out_path = format!("{}.unpacked", path_str);
        let data = match fs::read(&exe) {
            Ok(d) => d,
            Err(_) => continue,
        };

        if let Ok(pe) = PeFile::parse(&data) {
            if let Some(unpacker) = registry.find_unpacker(&pe) {
                println!("\n[MATCH FOUND] {} protected by: {}", exe.display(), unpacker.name());
                if unpacker.unpack(&pe, &out_path).is_ok() {
                    println!("[SUCCESS] Unpacked binary written to: {}", out_path);
                    unpacked_count += 1;
                }
            }
        }
    }

    println!("\nDirectory scan complete: {} SteamStub executable(s) unpacked.", unpacked_count);
}

fn find_exe_files(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Skip hidden directories
                if let Some(name) = path.file_name() {
                    if name.to_string_lossy().starts_with('.') {
                        continue;
                    }
                }
                find_exe_files(&path, files);
            } else if path.extension().map_or(false, |ext| ext.eq_ignore_ascii_case("exe")) {
                files.push(path);
            }
        }
    }
}
