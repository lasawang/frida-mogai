#!/usr/bin/env python3
"""
topatch.py - 编译产物后处理（借鉴看雪 rusda 文的 topatch 思路）

只处理 ELF 的 .rodata* 只读段，做两件事：
  1. 类型/组件名等长反转：FridaScriptEngine、GumScript、GLib-GIO、GDBusProxy
     这类字符串只影响外观、不参与协议协商，反转字节序后简单的固定串
     扫描就命中不了，且不改长度、不动布局。
  2. memfd 显示名替换：Frida 17 起 agent 走 memfd 加载，maps 里会出现
     "/memfd:frida-agent (deleted)"，名字本身就是特征。
     把 "frida-agent" 等长替换为伪装名（默认 jit-cache-1，
     可用 --seed 按构建随机生成，避免所有构建共用同一个替换名）。

与 patch_binary.py 的区别：那个是无差别全文替换（且替换串写死，
所有构建共用同一个假名、本身就是指纹）；本工具只动 .rodata、
用反转/随机两种方式，且跳过可执行段与 re.frida. 上下文。

用法:
  python3 topatch.py build/output/hlserver-arm64 [更多产物...]
  python3 topatch.py --seed 20261031 build/output/hlgadget-arm64.so
"""
import argparse
import random
import string
import struct
import sys

REVERSE_TARGETS = [b"FridaScriptEngine", b"GumScript", b"GLib-GIO", b"GDBusProxy"]
MEMFD_TARGET = b"frida-agent"
SKIP_CONTEXTS = [b"re.frida.", b"/re/frida/"]


def parse_sections(data):
    """返回 [(name, offset, size, is_exec)]，仅支持 ELF64 小端。"""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("not an ELF64 file")
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    e_shnum = struct.unpack_from("<H", data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", data, 62)[0]

    raw = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name_idx, _type = struct.unpack_from("<II", data, off)
        flags = struct.unpack_from("<Q", data, off + 8)[0]
        offset = struct.unpack_from("<Q", data, off + 24)[0]
        size = struct.unpack_from("<Q", data, off + 32)[0]
        raw.append((name_idx, offset, size, bool(flags & 0x4)))

    str_off, str_size = raw[e_shstrndx][1], raw[e_shstrndx][2]
    strtab = bytes(data[str_off:str_off + str_size])

    sections = []
    for name_idx, offset, size, is_exec in raw:
        end = strtab.find(b"\x00", name_idx)
        name = strtab[name_idx:end].decode("utf-8", "replace")
        sections.append((name, offset, size, is_exec))
    return sections


def memfd_replacement(seed):
    if seed is None:
        return b"jit-cache-1"  # 恰好 11 字节，与 frida-agent 等长
    rng = random.Random(seed)
    alphabet = string.ascii_lowercase + string.digits
    return ("jit-" + "".join(rng.choice(alphabet) for _ in range(7))).encode()


def patch_file(path, memfd_name):
    with open(path, "rb") as f:
        data = bytearray(f.read())
    sections = parse_sections(data)
    rodata = [(off, size) for name, off, size, is_exec in sections
              if name.startswith(".rodata") and not is_exec]
    if not rodata:
        print(f"[!] {path}: 未找到 .rodata 段，跳过")
        return

    def in_rodata(idx, length):
        return any(off <= idx and idx + length <= off + size
                   for off, size in rodata)

    def skipped_context(idx, length):
        window = bytes(data[max(0, idx - 20):idx + length + 20])
        return any(ctx in window for ctx in SKIP_CONTEXTS)

    counts = {"reverse": 0, "memfd": 0}
    jobs = [(t, t[::-1], "reverse") for t in REVERSE_TARGETS]
    jobs.append((MEMFD_TARGET, memfd_name, "memfd"))
    for old, new, kind in jobs:
        assert len(old) == len(new), (old, new)
        idx = 0
        while True:
            idx = data.find(old, idx)
            if idx == -1:
                break
            if in_rodata(idx, len(old)) and not skipped_context(idx, len(old)):
                data[idx:idx + len(old)] = new
                counts[kind] += 1
            idx += len(old)

    with open(path, "wb") as f:
        f.write(data)
    print(f"[+] {path}: 反转 {counts['reverse']} 处, memfd 名替换 {counts['memfd']} 处")


def main():
    ap = argparse.ArgumentParser(description="Post-build .rodata patcher")
    ap.add_argument("--seed", type=int, default=None,
                    help="给定种子时 memfd 伪装名按构建随机生成")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()
    name = memfd_replacement(args.seed)
    for path in args.files:
        patch_file(path, name)


if __name__ == "__main__":
    main()
