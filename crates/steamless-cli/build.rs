use std::process::Command;

fn main() {
    // Derive version from git tag (e.g. "v1.0.113" → "1.0.113", or "v1.0.113-3-gabcdef")
    let version = Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().trim_start_matches('v').to_string())
        .unwrap_or_else(|| "dev".to_string());

    println!("cargo:rustc-env=STEAMLESS_VERSION={version}");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
}
