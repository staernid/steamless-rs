<div align="center">
    <img width="200" src="assets/steamless.png" alt="steamless">
    </br>
</div>

<div align="center">
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=for-the-badge" alt="license" /></a>
</div>

# Steamless Portable (Rust Engine)

A high-performance, zero-dependency, ultra-portable rewrite of **Steamless** in Rust. 

Steamless removes the SteamStub DRM protection layer applied to applications and games released on Steam via the Steamworks SDK.

---

## ⚡ Features & Advantages over Legacy .NET Steamless

- **Zero Runtime Dependencies**: No .NET SDK, .NET Desktop Runtime, or Mono installation required.
- **Ultra-Fast & Lightweight**: Single ~1.5 MB native binary, starts in sub-millisecond time.
- **Universal Portability**: Compiles for Linux, Android (via Termux / NDK / Winlator / Mobox), Windows (x86/x64), macOS, and WebAssembly.
- **C ABI Shared Library (`libsteamless.so` / `steamless.dll`)**: Easily embedded in Android Wine emulators, Python launcher plugins (Lutris / Heroic / Proton), Java (JNI), and C/C++.
- **Full Variant Support**: Supports all 7 SteamStub DRM variants (v1.0, v2.0, v2.1, v3.0 x86/x64, v3.1/v3.1.2 x86/x64).

---

## 🐧 Linux Installation Guide

### Option 1: Fedora COPR (Fedora / RHEL / CentOS Stream)

Enable the COPR repository and install directly via `dnf`:

```bash
# Enable COPR repository
sudo dnf copr enable staernid/steamless

# Install CLI binary and shared library
sudo dnf install steamless
```

### Option 2: Install System-Wide via Cargo

```bash
# Install CLI binary to ~/.cargo/bin/steamless
cargo install --path crates/steamless-cli
```

### Option 3: Manual Binary & Library Installation

```bash
# Build release binaries
cargo build --release

# Install CLI binary to /usr/local/bin
sudo cp target/release/steamless /usr/local/bin/

# Install C shared library to /usr/local/lib
sudo cp target/release/libsteamless.so /usr/local/lib/
sudo ldconfig
```

---

## 🔌 Lutris & Linux Game Launchers Integration

Automate SteamStub DRM unpacking whenever launching games in Lutris, Heroic Games Launcher, or Steam Deck:

1. Open **Lutris** → Right-click Game → **Configure**.
2. Go to **System options** → Enable **Show advanced options**.
3. Under **Pre-launch script**, enter path:
   `/path/to/steamless-rs/plugins/lutris/steamless_lutris.py`
4. Check **Wait for pre-launch script to finish**.

Whenever you launch a game, Lutris automatically strips SteamStub DRM before starting Wine/Proton!

---

## 💻 C ABI / C/C++ & Android Integration

Exposes `extern "C"` functions for foreign language bindings:

```c
#include <stdint.h>

// Check if executable is protected
int32_t steamless_can_process(const char* file_path);

// Get DRM variant name (must call steamless_free_string on returned pointer)
char* steamless_get_variant(const char* file_path);

// Unpack executable
int32_t steamless_unpack(const char* input_path, const char* output_path);

// Free string pointer
void steamless_free_string(void* ptr);
```

---

## Supported Versions

- **SteamStub Variant 1.0** (x86)
- **SteamStub Variant 2.0 & 2.1** (x86)
- **SteamStub Variant 3.0 & 3.0.1** (x86 & x64)
- **SteamStub Variant 3.1 & 3.1.2** (x86 & x64)

---

## License & Disclaimers

Licensed under the **GNU General Public License v3.0** (`GPL-3.0`). See [LICENSE](LICENSE) for details.

Steamless is released for educational purposes in the hopes to learn and understand DRM technologies.
Steamless should only be used on games that you legally purchased and own. Do not distribute unpacked files.
