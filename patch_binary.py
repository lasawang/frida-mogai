import sys
import struct

FIXED_REPLACEMENT = b'xyzqw'

SKIP_CONTEXTS = [
    b'/re/frida/',
    b're.frida.',
]

def parse_elf_sections(data):
    """Parse ELF64 section headers to find executable sections."""
    if data[:4] != b'\x7fELF':
        return []

    e_shoff = struct.unpack_from('<Q', data, 40)[0]
    e_shentsize = struct.unpack_from('<H', data, 58)[0]
    e_shnum = struct.unpack_from('<H', data, 60)[0]

    exec_ranges = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_type = struct.unpack_from('<I', data, off + 4)[0]
        sh_flags = struct.unpack_from('<Q', data, off + 8)[0]
        sh_offset = struct.unpack_from('<Q', data, off + 24)[0]
        sh_size = struct.unpack_from('<Q', data, off + 32)[0]
        SHF_EXECINSTR = 0x4
        if sh_flags & SHF_EXECINSTR:
            exec_ranges.append((sh_offset, sh_offset + sh_size))

    return exec_ranges

def in_exec_range(idx, exec_ranges):
    for start, end in exec_ranges:
        if start <= idx < end:
            return True
    return False

def should_skip(data, idx, old):
    for ctx in SKIP_CONTEXTS:
        ctx_start = idx - 20
        if ctx_start < 0:
            ctx_start = 0
        window = data[ctx_start:idx + len(old) + 20]
        if ctx in window:
            return True
    return False

def patch_binary(filepath):
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    exec_ranges = parse_elf_sections(data)

    r_lower = FIXED_REPLACEMENT
    r_camel = r_lower[0:1].upper() + r_lower[1:]
    r_upper = r_lower.upper()

    replacements = [
        (b'FRIDA', r_upper),
        (b'Frida', r_camel),
        (b'frida', r_lower),
    ]

    count = 0
    skipped = 0
    skipped_exec = 0
    for old, new in replacements:
        idx = 0
        while True:
            idx = data.find(old, idx)
            if idx == -1:
                break
            if in_exec_range(idx, exec_ranges):
                skipped_exec += 1
                idx += len(old)
                continue
            if should_skip(data, idx, old):
                skipped += 1
                idx += len(old)
                continue
            data[idx:idx+len(old)] = new
            count += 1
            idx += len(old)

    with open(filepath, 'wb') as f:
        f.write(data)

    print(f'Patched {count} occurrences, skipped {skipped} (D-Bus), skipped {skipped_exec} (code section) in {filepath}')

if __name__ == '__main__':
    for path in sys.argv[1:]:
        patch_binary(path)
