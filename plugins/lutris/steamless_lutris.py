#!/usr/bin/env python3
"""
Lutris / Heroic Games Launcher DRM Unpacker Plugin
Integrates Steamless via native C ABI shared library (libsteamless.so / steamless.dll)
"""

import ctypes
import os
import sys

# Locate native shared library
plugin_dir = os.path.dirname(os.path.abspath(__file__))
repo_root = os.path.abspath(os.path.join(plugin_dir, "..", ".."))

# Search locations for libsteamless
so_candidates = [
    os.path.join(repo_root, "target", "release", "libsteamless.so"),
    os.path.join(repo_root, "target", "debug", "libsteamless.so"),
    os.path.join(plugin_dir, "libsteamless.so"),
    "/usr/local/lib/libsteamless.so",
    "/usr/lib/libsteamless.so"
]

steamless_so = None
for candidate in so_candidates:
    if os.path.exists(candidate):
        steamless_so = candidate
        break

if not steamless_so:
    # Build release shared library if cargo is available
    workspace_manifest = os.path.join(repo_root, "Cargo.toml")
    if os.path.exists(workspace_manifest):
        os.system(f"cargo build --manifest-path {workspace_manifest} --release")
        rel_so = os.path.join(repo_root, "target", "release", "libsteamless.so")
        if os.path.exists(rel_so):
            steamless_so = rel_so

if not steamless_so:
    print("[Steamless Lutris Plugin] Error: Unable to locate libsteamless.so")
    sys.exit(1)

# Load native library via C ABI
lib = ctypes.CDLL(steamless_so)

lib.steamless_can_process.argtypes = [ctypes.c_char_p]
lib.steamless_can_process.restype = ctypes.c_int

lib.steamless_get_variant.argtypes = [ctypes.c_char_p]
lib.steamless_get_variant.restype = ctypes.c_void_p

lib.steamless_unpack.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.steamless_unpack.restype = ctypes.c_int

lib.steamless_free_string.argtypes = [ctypes.c_void_p]
lib.steamless_free_string.restype = None

def lutris_pre_launch_hook(game_exe_path):
    """
    Lutris / Heroic pre-launch hook function.
    Checks if game executable is protected by SteamStub DRM and unpacks it if needed.
    Returns path to clean executable to launch.
    """
    if not os.path.exists(game_exe_path):
        return game_exe_path

    exe_bytes = game_exe_path.encode('utf-8')
    can_process = lib.steamless_can_process(exe_bytes)

    if can_process == 1:
        variant_ptr = lib.steamless_get_variant(exe_bytes)
        variant_name = "SteamStub"
        if variant_ptr:
            variant_name = ctypes.string_at(variant_ptr).decode('utf-8')
            lib.steamless_free_string(variant_ptr)

        print(f"[Steamless Lutris Plugin] Protected by {variant_name}")
        unpacked_exe = f"{game_exe_path}.unpacked.exe"
        
        # Unpack if not already unpacked or if source file is newer
        if not os.path.exists(unpacked_exe) or os.path.getmtime(game_exe_path) > os.path.getmtime(unpacked_exe):
            res = lib.steamless_unpack(exe_bytes, unpacked_exe.encode('utf-8'))
            if res == 0:
                print(f"[Steamless Lutris Plugin] Unpacked -> {unpacked_exe}")
                return unpacked_exe
            else:
                print(f"[Steamless Lutris Plugin] Unpacking failed with status code {res}")
        else:
            return unpacked_exe

    return game_exe_path

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        out = lutris_pre_launch_hook(target)
        print(f"Resulting executable: {out}")
    else:
        print("Usage: steamless_lutris.py <game_executable.exe>")
