#!/usr/bin/env python3
"""
spawn_run.py - 通用 Spawn 运行器（本项目推荐的默认注入方式）

为什么 spawn 优先（而不是 attach）:
  1. attach 时 App 的 .init_array / JNI_OnLoad 里的检测代码早已跑完，
     TracerPid 在注入瞬间还会置位几百毫秒，卡启动窗口轮询的检测一读就抓。
  2. spawn 让进程停在 Zygote 门控点：先把全部 bypass 脚本装好再 resume，
     检测代码第一次运行时，过滤 hook 已经就位。

用法:
  # 经 deploy.sh 的 unix socket 转发口连接（默认 127.0.0.1:38502）
  python3 spawn_run.py com.target.app
  # 自定义脚本（在 bypass 脚本之后加载）
  python3 spawn_run.py com.target.app -l my_hook.js
  # USB 直连的标准 frida-server
  python3 spawn_run.py com.target.app -U
  # 存活观察 300 秒后自动退出
  python3 spawn_run.py com.target.app --duration 300

注意（patch 0001 的配套关系）:
  若编译时启用了 0001（改 frida:rpc 协议标识），宿主机上的 frida
  Python 包/frida-tools 必须出自同一套 patch 的 frida-core，
  否则 spawn 握手阶段就会失败——attach 偶尔能连上、spawn 连不上，
  十有八九是这个原因。对外分发的 server 建议不打 0001。
"""
import argparse
import os
import sys
import time

import frida

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BYPASS_DIR = os.path.join(ROOT, "scripts", "bypass")

# resume 前必须装好的顺序：反调试最先（检测多在 init 早期），
# 然后线程改名（趁 gum 线程刚起、检测轮询未开始），最后 Java 层。
DEFAULT_SCRIPTS = ["anti_debug.js", "hide_threads.js", "anti_frida.js"]
OPTIONAL_SCRIPTS = {
    "root": "anti_root.js",
    "ssl": "ssl_pinning.js",
    "syscall": "syscall_hook.js",
    "time": "time_patch.js",
}


def build_source(args):
    parts = []
    names = list(DEFAULT_SCRIPTS)
    for key, fname in OPTIONAL_SCRIPTS.items():
        if getattr(args, key):
            names.append(fname)
    for fname in names:
        path = os.path.join(BYPASS_DIR, fname)
        with open(path, "r", encoding="utf-8") as f:
            parts.append("// ===== %s =====\n" % fname + f.read())
        print("[*] bypass: %s" % fname)
    for extra in args.load or []:
        with open(extra, "r", encoding="utf-8") as f:
            parts.append("// ===== %s =====\n" % extra + f.read())
        print("[*] script: %s" % extra)
    return "\n".join(parts)


def main():
    ap = argparse.ArgumentParser(description="Spawn-first Frida runner")
    ap.add_argument("package", help="目标包名，如 com.target.app")
    ap.add_argument("-H", "--host", default="127.0.0.1:38502",
                    help="remote device 地址（默认 deploy.sh 的转发口）")
    ap.add_argument("-U", "--usb", action="store_true", help="改用 USB 设备")
    ap.add_argument("-l", "--load", action="append",
                    help="额外加载的 JS 脚本（可多次）")
    ap.add_argument("--root", action="store_true", help="加载 anti_root.js")
    ap.add_argument("--ssl", action="store_true", help="加载 ssl_pinning.js")
    ap.add_argument("--syscall", action="store_true",
                    help="加载 syscall_hook.js（开销大，仅调试期）")
    ap.add_argument("--time", action="store_true", help="加载 time_patch.js")
    ap.add_argument("--duration", type=int, default=0,
                    help="存活观察秒数，0 = 一直挂着直到 Ctrl+C")
    args = ap.parse_args()

    if args.usb:
        device = frida.get_usb_device()
    else:
        device = frida.get_device_manager().add_remote_device(args.host)
    print("[*] device: %s" % device.name)

    pid = device.spawn([args.package])
    print("[*] spawned %s pid=%d（进程已挂起，检测代码尚未运行）" % (args.package, pid))
    session = device.attach(pid)

    script = session.create_script(build_source(args))
    script.on("message", lambda msg, _:
              print("  [%s] %s" % (msg.get("type"), msg.get("payload", msg))))
    script.load()
    device.resume(pid)
    print("[+] resumed，bypass 已在 resume 前全部就位")

    start = time.time()
    try:
        while True:
            time.sleep(5)
            elapsed = int(time.time() - start)
            alive = any(p.pid == pid for p in device.enumerate_processes())
            if not alive:
                print("[!] 目标进程已退出（%ds）——多半是被检测杀掉，" % elapsed +
                      "按 docs/detection_checklist.md 的排查流程定位")
                return 1
            if elapsed % 30 == 0:
                print("  alive %ds" % elapsed)
            if args.duration and elapsed >= args.duration:
                print("[+] 存活达到 %ds，测试通过" % args.duration)
                return 0
    except KeyboardInterrupt:
        print("\n[*] 退出（进程保持运行，session 随本进程结束而卸载）")
        return 0


if __name__ == "__main__":
    sys.exit(main())
