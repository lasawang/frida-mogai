#!/usr/bin/env python3
"""
重新应用二进制 patch 到预编译的 GLib/GIO 静态库
这些修改不在 git diff 中，需要单独处理

目标: 修改线程名避免检测
- libglib-2.0.a: "gmain\0" -> "htrim\0", "pool-%s\0" -> "tsk0-%s\0"
- libgio-2.0.a:  "gdbus\0" -> "atsvc\0"
"""
import struct
import sys
import os

SDK_DIR = "/Volumes/Shared/ai_reverse/frida_mogai/frida_src/deps/sdk-android-arm64/lib"

PATCHES = [
    {
        "file": f"{SDK_DIR}/libglib-2.0.a",
        "replacements": [
            (b"gmain\x00", b"htrim\x00"),
            (b"pool-%s\x00", b"tsk0-%s\x00"),
        ]
    },
    {
        "file": f"{SDK_DIR}/libgio-2.0.a",
        "replacements": [
            (b"gdbus\x00", b"atsvc\x00"),
        ]
    },
]

def patch_binary(filepath, replacements):
    with open(filepath, 'rb') as f:
        data = f.read()

    original = data
    for old, new in replacements:
        if len(old) != len(new):
            print(f"  ERROR: length mismatch {old!r} ({len(old)}) vs {new!r} ({len(new)})")
            continue
        count = data.count(old)
        if count == 0:
            # Check if already patched
            if data.count(new) > 0:
                print(f"  SKIP: {old!r} -> {new!r} (already patched)")
            else:
                print(f"  WARN: {old!r} not found!")
            continue
        data = data.replace(old, new)
        print(f"  OK: {old!r} -> {new!r} ({count} occurrences)")

    if data != original:
        with open(filepath, 'wb') as f:
            f.write(data)
        print(f"  Written: {filepath}")
    else:
        print(f"  No changes needed")

def main():
    for patch in PATCHES:
        filepath = patch["file"]
        print(f"\n[*] Patching {os.path.basename(filepath)}...")
        if not os.path.exists(filepath):
            print(f"  ERROR: file not found: {filepath}")
            continue
        patch_binary(filepath, patch["replacements"])

    print("\n[+] Binary patches complete.")

if __name__ == "__main__":
    main()
