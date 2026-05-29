#!/usr/bin/env python3
"""
Frida 源码魔改脚本 v2 - 精确版
只修改运行时可被检测到的字符串字面量，不动构建系统的文件名/头文件引用。

策略：
- 只改引号内的字符串（Vala 的 "..." 和 C 的 "..."）
- 不改 #include、文件路径、变量名、函数名
- 对 Vala namespace Frida 不做修改（会破坏编译），改为编译后对二进制做处理
"""

import os
import re
import sys
import json
import secrets
import string
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent
FRIDA_SRC = BASE_DIR / "frida_src"
FRIDA_CORE = FRIDA_SRC / "subprojects" / "frida-core"
FRIDA_GUM = FRIDA_SRC / "subprojects" / "frida-gum"
MANIFEST_FILE = BASE_DIR / "build" / "modify_manifest.json"


def gen_hex(length):
    return secrets.token_hex(length)

def gen_alpha_lower(length):
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(length))

def gen_c_symbol(length):
    first = secrets.choice(string.ascii_lowercase + "_")
    rest = "".join(secrets.choice(string.ascii_lowercase + string.digits + "_") for _ in range(length - 1))
    return first + rest

def gen_thread_name():
    prefixes = ["sys", "hw", "binder", "jit", "gc", "pool", "work", "async"]
    suffixes = ["loop", "svc", "mgr", "proc", "task", "mon", "io"]
    p = secrets.choice(prefixes)
    s = secrets.choice(suffixes)
    n = secrets.choice(string.digits)
    sep = secrets.choice(["-", "_", ""])
    return f"{p}{sep}{s}{n}"

def gen_reverse_domain():
    words = ["io", "com", "org", "net", "dev"]
    tld = secrets.choice(words)
    name = gen_alpha_lower(6)
    sub = gen_alpha_lower(4)
    return f"{tld}.{name}.{sub}"


class PreciseModifier:
    def __init__(self):
        self.changes = []
        self.errors = []

    def replace_string_in_file(self, filepath, old_str, new_str, desc=""):
        """精确替换文件中的字符串字面量"""
        filepath = Path(filepath)
        if not filepath.exists():
            self.errors.append(f"File not found: {filepath}")
            return 0

        content = filepath.read_text(encoding="utf-8")
        count = content.count(old_str)
        if count == 0:
            return 0

        new_content = content.replace(old_str, new_str)
        filepath.write_text(new_content, encoding="utf-8")
        self.changes.append({"file": str(filepath), "old": old_str, "new": new_str, "count": count, "desc": desc})
        print(f"  [+] {filepath.name}: '{old_str}' => '{new_str}' ({count}x) - {desc}")
        return count


def main():
    print("=" * 60)
    print("  Frida Source Modifier v2 (Precise)")
    print("=" * 60)

    if not FRIDA_CORE.exists():
        print(f"\n[!] frida-core not found at: {FRIDA_CORE}")
        sys.exit(1)

    mod = PreciseModifier()

    # 生成随机值
    # IMPORTANT: rpc_id must be same length as "frida:rpc" (9 bytes)
    rpc_id = gen_alpha_lower(4) + ":" + gen_alpha_lower(4)  # 9 bytes like "xxxx:yyyy"
    # IMPORTANT: dbus_prefix must be same length as "re.frida" (8 bytes)
    dbus_prefix = gen_alpha_lower(2) + "." + gen_alpha_lower(5)  # 8 bytes like "xx.yyyyy"
    agent_sym = gen_c_symbol(14)
    thread_js = gen_thread_name()
    thread_server = gen_thread_name()
    thread_emulated = gen_thread_name()
    thread_container = gen_thread_name()
    selinux_type = gen_alpha_lower(6) + "_file"
    server_dir_name = gen_alpha_lower(8)

    print(f"\n[*] Random values:")
    print(f"  rpc_id:          {rpc_id}")
    print(f"  dbus_prefix:     {dbus_prefix}")
    print(f"  agent_sym:       {agent_sym}")
    print(f"  thread_js:       {thread_js}")
    print(f"  thread_server:   {thread_server}")
    print(f"  thread_emulated: {thread_emulated}")
    print(f"  thread_container:{thread_container}")
    print(f"  selinux_type:    {selinux_type}")
    print(f"  server_dir_name: {server_dir_name}")

    # NOTE: frida:rpc 和 re.frida D-Bus 接口名是 client-server 协议的一部分
    # 修改它们需要同步修改客户端，所以这里不动，保持兼容性
    # 目标 APP 检测不到这些（它们在 server 进程内，不在被注入的 agent 中）
    print("\n[*] 1-2. SKIPPED: RPC/D-Bus protocol (client-server only, not visible to target app)")

    # ============================================================
    # 3. Server 目录名和线程名
    # ============================================================
    print("\n[*] 3. Server directory and thread names")
    server_file = FRIDA_CORE / "server" / "server.vala"
    # DEFAULT_DIRECTORY 字符串
    mod.replace_string_in_file(server_file, '"re.frida.server"',
                               f'"re.frida.{server_dir_name}"', "Server directory name")
    # 线程名
    mod.replace_string_in_file(server_file, '"frida-server-main-loop"',
                               f'"{thread_server}"', "Server thread name")
    # frida-policyd 进程名检测
    mod.replace_string_in_file(server_file, '"frida-policyd"',
                               f'"{server_dir_name}d"', "policyd name")

    # ============================================================
    # 4. Agent 导出符号名（内存特征 - 关键）
    # ============================================================
    print("\n[*] 4. Agent export symbol 'frida_agent_main'")
    # 这些是字符串字面量引用（用于 dlsym 查找）
    symbol_files = [
        FRIDA_CORE / "src" / "agent-container.vala",
        FRIDA_CORE / "src" / "darwin" / "darwin-host-session.vala",
        FRIDA_CORE / "src" / "linux" / "linux-host-session.vala",
        FRIDA_CORE / "src" / "freebsd" / "freebsd-host-session.vala",
        FRIDA_CORE / "src" / "qnx" / "qnx-host-session.vala",
        FRIDA_CORE / "src" / "windows" / "windows-host-session.vala",
    ]
    for f in symbol_files:
        mod.replace_string_in_file(f, '"frida_agent_main"', f'"{agent_sym}"', "Agent entrypoint symbol")

    # agent-glue.c: 函数调用（不是字符串，是实际的 C 函数名）
    # 这里需要添加包装函数而不是简单替换
    agent_glue = FRIDA_CORE / "lib" / "agent" / "agent-glue.c"
    content = agent_glue.read_text()
    # 在 #endif 前添加包装函数
    wrapper = f"""
__attribute__ ((visibility ("default"))) void
{agent_sym} (const char * agent_parameters, FridaUnloadPolicy * unload_policy, void * injector_state)
{{
  frida_agent_main (agent_parameters, unload_policy, injector_state);
}}

"""
    content = content.replace("#ifdef HAVE_ANDROID", wrapper + "#ifdef HAVE_ANDROID")
    agent_glue.write_text(content)
    print(f"  [+] agent-glue.c: added wrapper function '{agent_sym}'")
    mod.changes.append({"file": str(agent_glue), "desc": "Added export wrapper", "count": 1})

    # version script
    version_file = FRIDA_CORE / "lib" / "agent" / "frida-agent.version"
    mod.replace_string_in_file(version_file, "frida_agent_main", agent_sym, "Version script export")

    # ============================================================
    # 5. Agent SO 文件名模板（内存特征）
    # ============================================================
    print("\n[*] 5. Agent SO filename template")
    linux_session = FRIDA_CORE / "src" / "linux" / "linux-host-session.vala"
    so_name = gen_alpha_lower(7)
    mod.replace_string_in_file(linux_session, '"frida-agent-<arch>.so"',
                               f'"{so_name}-<arch>.so"', "Agent SO template")
    mod.replace_string_in_file(linux_session, '"frida-agent-arm.so"',
                               f'"{so_name}-arm.so"', "Agent SO arm")
    mod.replace_string_in_file(linux_session, '"frida-agent-arm64.so"',
                               f'"{so_name}-arm64.so"', "Agent SO arm64")

    # ============================================================
    # 6. Agent 线程名（线程层检测）
    # ============================================================
    print("\n[*] 6. Agent thread names")
    agent_vala = FRIDA_CORE / "lib" / "agent" / "agent.vala"
    mod.replace_string_in_file(agent_vala, '"frida-agent-emulated"',
                               f'"{thread_emulated}"', "Agent emulated thread")

    agent_container = FRIDA_CORE / "src" / "agent-container.vala"
    mod.replace_string_in_file(agent_container, '"frida-agent-container"',
                               f'"{thread_container}"', "Agent container thread")

    # ============================================================
    # 7. gum-js-loop 线程名（线程层检测 - 关键）
    # ============================================================
    print("\n[*] 7. Gum JS thread name")
    scheduler_c = FRIDA_GUM / "bindings" / "gumjs" / "gumscriptscheduler.c"
    mod.replace_string_in_file(scheduler_c, '"gum-js-loop"',
                               f'"{thread_js}"', "JS scheduler thread")

    # ============================================================
    # 8. SELinux 标签（文件系统检测）
    # ============================================================
    print("\n[*] 8. SELinux labels")
    selinux_c = FRIDA_CORE / "lib" / "selinux" / "patch.c"
    mod.replace_string_in_file(selinux_c, '"frida_file"',
                               f'"{selinux_type}"', "SELinux type")

    pipe_vala = FRIDA_CORE / "lib" / "pipe" / "pipe.vala"
    mod.replace_string_in_file(pipe_vala, "frida_file", selinux_type, "SELinux context")

    linjector_vala = FRIDA_CORE / "src" / "linux" / "linjector.vala"
    mod.replace_string_in_file(linjector_vala, "frida_file", selinux_type, "SELinux context")

    # ============================================================
    # 9. 错误消息中的 "frida-server" 引用
    # ============================================================
    print("\n[*] 9. Error messages")
    droidy = FRIDA_CORE / "src" / "droidy" / "droidy-host-session.vala"
    mod.replace_string_in_file(droidy, "remote frida-server", "remote server", "Error message")
    mod.replace_string_in_file(droidy, "Incompatible frida-server", "Incompatible server", "Error message")

    fruity = FRIDA_CORE / "src" / "fruity" / "fruity-host-session.vala"
    mod.replace_string_in_file(fruity, "remote frida-server", "remote server", "Error message")
    mod.replace_string_in_file(fruity, "Incompatible frida-server", "Incompatible server", "Error message")

    host_session = FRIDA_CORE / "src" / "host-session-service.vala"
    mod.replace_string_in_file(host_session, "load frida-agent", "load agent", "Error message")

    # ============================================================
    # 10. 内部 JS 路径
    # ============================================================
    print("\n[*] 10. Internal JS path")
    barebone = FRIDA_CORE / "src" / "barebone" / "script.vala"
    mod.replace_string_in_file(barebone, '"/_frida.js"', '"/_runtime.js"', "Internal JS path")

    # ============================================================
    # 保存 manifest
    # ============================================================
    manifest = {
        "timestamp": datetime.now().isoformat(),
        "values": {
            "rpc_id": rpc_id,
            "dbus_prefix": dbus_prefix,
            "agent_sym": agent_sym,
            "so_name": so_name,
            "thread_js": thread_js,
            "thread_server": thread_server,
            "thread_emulated": thread_emulated,
            "thread_container": thread_container,
            "selinux_type": selinux_type,
            "server_dir_name": server_dir_name,
        },
        "changes": mod.changes,
        "errors": mod.errors,
    }
    MANIFEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_FILE.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

    # ============================================================
    # 验证
    # ============================================================
    print("\n[*] === Verification ===")
    checks = {
        "frida:rpc": FRIDA_CORE / "lib" / "base" / "rpc.vala",
        "re.frida.server": FRIDA_CORE / "server" / "server.vala",
        "frida-server-main-loop": FRIDA_CORE / "server" / "server.vala",
        '"frida_agent_main"': FRIDA_CORE / "src" / "linux" / "linux-host-session.vala",
        '"gum-js-loop"': FRIDA_GUM / "bindings" / "gumjs" / "gumscriptscheduler.c",
    }
    all_pass = True
    for pattern, filepath in checks.items():
        if filepath.exists():
            content = filepath.read_text()
            if pattern in content:
                print(f"  [FAIL] '{pattern}' still in {filepath.name}")
                all_pass = False
            else:
                print(f"  [PASS] '{pattern}' removed from {filepath.name}")

    print(f"\n[*] Total modifications: {sum(c.get('count', 0) for c in mod.changes)}")
    if mod.errors:
        print(f"[!] Errors: {len(mod.errors)}")
        for e in mod.errors:
            print(f"  - {e}")

    if all_pass:
        print("\n[*] All key fingerprints replaced successfully!")
    print("[*] Note: GObject type names (FridaXxx) will be handled post-build via binary patching.")
    print("\n[*] Next: run 'make' in frida_src/ to compile.")


if __name__ == "__main__":
    main()
