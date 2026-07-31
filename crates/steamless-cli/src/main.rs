use std::env;
use std::fs;
use steamless_core::pe::PeFile;
use steamless_core::unpackers::UnpackerRegistry;

fn main() {
    println!("==================================================");
    println!("  Steamless Engine (Portable Native Rust Edition)  ");
    println!("==================================================");

    let registry = UnpackerRegistry::new();
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("\nRegistered Unpacker Plugins:");
        for (name, version, is_64bit) in registry.list_plugins() {
            let arch = if is_64bit { "x64" } else { "x86" };
            println!("  - [{}] {} (v{})", arch, name, version);
        }
        println!("\nUsage: steamless <target_executable.exe> [output_executable.exe]");
        return;
    }

    let input_path = &args[1];
    let output_path = if args.len() > 2 {
        args[2].clone()
    } else {
        format!("{}.unpacked.exe", input_path)
    };

    println!("\nInspecting executable: {}", input_path);
    let data = match fs::read(input_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            std::process::exit(1);
        }
    };

    match PeFile::parse(&data) {
        Ok(pe) => {
            println!("  PE Architecture: {}", if pe.is_64bit() { "64-bit (PE32+)" } else { "32-bit (PE32)" });
            println!("  Entry Point RVA: 0x{:08X}", pe.entry_point());
            println!("  Image Base:      0x{:016X}", pe.image_base());

            if let Some(unpacker) = registry.find_unpacker(&pe) {
                println!("\n[MATCH FOUND] Protected by: {}", unpacker.name());
                match unpacker.unpack(&pe, &output_path) {
                    Ok(_) => {
                        println!("[SUCCESS] Unpacked binary written to: {}", output_path);
                        std::process::exit(0);
                    }
                    Err(err) => {
                        eprintln!("[ERROR] Unpacking failed: {}", err);
                        std::process::exit(2);
                    }
                }
            } else {
                println!("\n[INFO] Executable is clean or uses an unsupported DRM variant.");
                std::process::exit(0);
            }
        }
        Err(err) => {
            eprintln!("Failed to parse PE headers: {}", err);
            std::process::exit(1);
        }
    }
}
