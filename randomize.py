#!/usr/bin/env python3
"""
Frida Patch Randomizer
每次运行生成独立的随机特征串，替换 patch 文件中的占位符，
确保编译产物不会被加固方通过固定特征串识别。
"""

import os
import re
import sys
import json
import secrets
import string
import shutil
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent
PATCHES_DIR = BASE_DIR / "patches"
OUTPUT_DIR = BASE_DIR / "build" / "patches_randomized"
MANIFEST_FILE = BASE_DIR / "build" / "randomize_manifest.json"

# 需要随机化的特征串映射表
# key: patch 文件中的占位符标记（用 @@PLACEHOLDER@@ 格式）
# value: 生成规则描述
REPLACEMENTS = {
    "@@FRIDA_RPC@@": {
        "description": "frida:rpc 协议标识替换",
        "generator": "hex",
        "length": 5,
    },
    "@@RE_FRIDA_SERVER@@": {
        "description": "re.frida.server D-Bus 服务名替换",
        "generator": "reverse_domain",
        "length": 0,
    },
    "@@LINJECTOR@@": {
        "description": "linjector 管道名替换",
        "generator": "alpha_lower",
        "length": 8,
    },
    "@@FRIDA_AGENT_SO@@": {
        "description": "frida-agent.so 文件名替换",
        "generator": "so_name",
        "length": 0,
    },
    "@@FRIDA_AGENT_MAIN@@": {
        "description": "frida_agent_main 导出符号替换",
        "generator": "c_symbol",
        "length": 12,
    },
    "@@GUM_JS_LOOP@@": {
        "description": "gum-js-loop 线程名替换",
        "generator": "thread_name",
        "length": 0,
    },
    "@@GMAIN@@": {
        "description": "gmain 线程名替换",
        "generator": "thread_name",
        "length": 0,
    },
    "@@POOL_FRIDA@@": {
        "description": "pool-frida 线程池名替换",
        "generator": "thread_name",
        "length": 0,
    },
    "@@GDBUS@@": {
        "description": "gdbus 线程名替换",
        "generator": "thread_name",
        "length": 0,
    },
    "@@GUMSCRIPT@@": {
        "description": "GumScript 内部字符串替换",
        "generator": "camel_case",
        "length": 9,
    },
    "@@LIBFRIDA@@": {
        "description": "LIBFRIDA 标识替换",
        "generator": "upper_alpha",
        "length": 8,
    },
    "@@SERVER_NAME@@": {
        "description": "frida-server 进程名替换",
        "generator": "process_name",
        "length": 0,
    },
}


def gen_hex(length: int) -> str:
    return secrets.token_hex(length)


def gen_alpha_lower(length: int) -> str:
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(length))


def gen_upper_alpha(length: int) -> str:
    return "".join(secrets.choice(string.ascii_uppercase) for _ in range(length))


def gen_c_symbol(length: int) -> str:
    first = secrets.choice(string.ascii_lowercase + "_")
    rest = "".join(
        secrets.choice(string.ascii_lowercase + string.digits + "_")
        for _ in range(length - 1)
    )
    return first + rest


def gen_camel_case(length: int) -> str:
    vowels = "aeiou"
    consonants = "bcdfghjklmnpqrstvwxyz"
    result = []
    for i in range(length):
        if i == 0:
            result.append(secrets.choice(consonants).upper())
        elif i % 2 == 0:
            result.append(secrets.choice(consonants))
        else:
            result.append(secrets.choice(vowels))
    return "".join(result)


def gen_reverse_domain() -> str:
    words = ["io", "com", "org", "net", "dev"]
    tld = secrets.choice(words)
    name = gen_alpha_lower(6)
    sub = gen_alpha_lower(4)
    return f"{tld}.{name}.{sub}"


def gen_so_name() -> str:
    prefixes = ["lib", ""]
    prefix = secrets.choice(prefixes)
    name = gen_alpha_lower(7)
    return f"{prefix}{name}.so"


def gen_thread_name() -> str:
    prefixes = ["sys", "hw", "binder", "jit", "gc", "pool", "work"]
    suffixes = ["loop", "svc", "mgr", "proc", "task", "mon"]
    p = secrets.choice(prefixes)
    s = secrets.choice(suffixes)
    n = secrets.choice(string.digits)
    sep = secrets.choice(["-", "_", ""])
    return f"{p}{sep}{s}{n}"


def gen_process_name() -> str:
    names = [
        "logd", "servicemanager", "vold", "installd",
        "lmkd", "storaged", "thermalserviced", "gpuservice",
        "cameraserver", "mediaserver", "audioserver",
    ]
    base = secrets.choice(names)
    suffix = secrets.choice(["", "64", "_helper", "d"])
    return base + suffix


def generate_value(rule: dict) -> str:
    gen_type = rule["generator"]
    length = rule["length"]

    generators = {
        "hex": lambda: gen_hex(length),
        "alpha_lower": lambda: gen_alpha_lower(length),
        "upper_alpha": lambda: gen_upper_alpha(length),
        "c_symbol": lambda: gen_c_symbol(length),
        "camel_case": lambda: gen_camel_case(length),
        "reverse_domain": gen_reverse_domain,
        "so_name": gen_so_name,
        "thread_name": gen_thread_name,
        "process_name": gen_process_name,
    }

    generator = generators.get(gen_type)
    if not generator:
        raise ValueError(f"Unknown generator type: {gen_type}")
    return generator()


def randomize_patches(input_dir: Path, output_dir: Path) -> dict:
    """读取 patch 文件，替换占位符，输出到目标目录"""

    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    # 生成本次的随机值
    mapping = {}
    for placeholder, rule in REPLACEMENTS.items():
        value = generate_value(rule)
        mapping[placeholder] = {
            "value": value,
            "description": rule["description"],
        }

    # 遍历所有 patch 文件
    patch_files = list(input_dir.rglob("*.patch"))
    if not patch_files:
        print(f"[!] No patch files found in {input_dir}")
        return mapping

    for patch_file in patch_files:
        rel_path = patch_file.relative_to(input_dir)
        out_file = output_dir / rel_path
        out_file.parent.mkdir(parents=True, exist_ok=True)

        content = patch_file.read_text(encoding="utf-8")

        for placeholder, info in mapping.items():
            content = content.replace(placeholder, info["value"])

        out_file.write_text(content, encoding="utf-8")
        print(f"  [+] {rel_path}")

    return mapping


def save_manifest(mapping: dict):
    """保存本次随机化的映射关系，方便调试"""
    manifest = {
        "timestamp": datetime.now().isoformat(),
        "mappings": {k: v["value"] for k, v in mapping.items()},
        "details": mapping,
    }
    MANIFEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_FILE.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"\n  [*] Manifest saved to {MANIFEST_FILE}")


def main():
    print("[*] Frida Patch Randomizer")
    print(f"[*] Input:  {PATCHES_DIR}")
    print(f"[*] Output: {OUTPUT_DIR}")
    print()

    if not PATCHES_DIR.exists():
        print(f"[!] Patches directory not found: {PATCHES_DIR}")
        sys.exit(1)

    print("[*] Generating random values...")
    mapping = randomize_patches(PATCHES_DIR, OUTPUT_DIR)

    print("\n[*] Randomization mapping:")
    for placeholder, info in mapping.items():
        print(f"  {placeholder} => {info['value']}")

    save_manifest(mapping)
    print("\n[*] Done. Use patches from build/patches_randomized/ for compilation.")


if __name__ == "__main__":
    main()
