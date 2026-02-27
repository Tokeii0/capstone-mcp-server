"""CTF-oriented utilities: ROP gadgets, string extraction, XOR, pattern offset, crypto detection, shellcode analysis."""

import re
import string
from typing import Optional

from capstone import (
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_GRP_RET,
    CS_GRP_JUMP,
    CS_GRP_CALL,
    CS_GRP_INT,
    Cs,
)

from .disassembler import ArchType, ARCH_MAP, create_engine


# ═══════════════════════════════════════════════
# 1. ROP Gadget Finder
# ═══════════════════════════════════════════════

def find_rop_gadgets(
    code: bytes,
    arch: ArchType,
    base_address: int = 0,
    max_gadget_len: int = 5,
    max_results: int = 200,
) -> list[dict]:
    """Find ROP gadgets (instruction sequences ending with ret/retf/retfq).

    Scans every byte offset for sequences that end with a ret-type instruction.
    """
    cs_arch, cs_mode = ARCH_MAP[arch]
    md = Cs(cs_arch, cs_mode)
    md.detail = True
    md.skipdata = False

    # Determine ret opcodes to search for based on architecture
    if cs_arch == CS_ARCH_X86:
        ret_bytes = [b"\xc3", b"\xc2", b"\xcb", b"\xca"]  # ret, ret imm16, retf, retf imm16
    else:
        ret_bytes = [b"\xc3"]  # fallback

    gadgets: dict[str, dict] = {}

    for ret_byte in ret_bytes:
        positions = []
        start = 0
        while True:
            pos = code.find(ret_byte, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1

        for ret_pos in positions:
            # Try different starting offsets before the ret
            for back in range(1, max_gadget_len * 15 + 1):
                start_pos = ret_pos - back
                if start_pos < 0:
                    continue

                snippet = code[start_pos:ret_pos + len(ret_byte)]
                insns = list(md.disasm(snippet, base_address + start_pos))

                if not insns:
                    continue

                # Check that the last instruction is ret and it ends exactly at ret_pos + len(ret_byte)
                last = insns[-1]
                last_end = last.address + last.size
                expected_end = base_address + ret_pos + len(ret_byte)

                if last_end != expected_end:
                    continue
                if not last.group(CS_GRP_RET):
                    continue
                if len(insns) > max_gadget_len:
                    continue

                # Filter out gadgets with invalid/skip-data instructions
                valid = True
                for ins in insns:
                    if ins.mnemonic == ".byte":
                        valid = False
                        break
                if not valid:
                    continue

                gadget_str = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in insns)
                addr = base_address + start_pos

                if gadget_str not in gadgets:
                    gadgets[gadget_str] = {
                        "address": f"0x{addr:x}",
                        "gadget": gadget_str,
                        "bytes": snippet.hex(),
                        "length": len(insns),
                    }

                if len(gadgets) >= max_results:
                    break
            if len(gadgets) >= max_results:
                break
        if len(gadgets) >= max_results:
            break

    return sorted(gadgets.values(), key=lambda g: int(g["address"], 16))


# ═══════════════════════════════════════════════
# 2. String Extraction
# ═══════════════════════════════════════════════

def extract_strings(
    data: bytes,
    min_length: int = 4,
    encoding: str = "both",
    max_results: int = 500,
) -> list[dict]:
    """Extract printable strings from binary data.

    Args:
        data: Raw binary data.
        min_length: Minimum string length.
        encoding: "ascii", "utf16le", or "both".
        max_results: Maximum number of strings to return.
    """
    results: list[dict] = []

    # ASCII strings
    if encoding in ("ascii", "both"):
        printable = set(string.printable.encode("ascii")) - {0x0b, 0x0c}
        current = bytearray()
        start_offset = 0
        for i, b in enumerate(data):
            if b in printable and b != 0:
                if not current:
                    start_offset = i
                current.append(b)
            else:
                if len(current) >= min_length:
                    s = current.decode("ascii", errors="replace").strip()
                    if s:
                        results.append({
                            "offset": f"0x{start_offset:x}",
                            "encoding": "ascii",
                            "length": len(s),
                            "string": s,
                        })
                current = bytearray()
        if len(current) >= min_length:
            s = current.decode("ascii", errors="replace").strip()
            if s:
                results.append({
                    "offset": f"0x{start_offset:x}",
                    "encoding": "ascii",
                    "length": len(s),
                    "string": s,
                })

    # UTF-16 LE strings
    if encoding in ("utf16le", "both"):
        i = 0
        while i < len(data) - 1:
            current_chars = []
            start_offset = i
            while i < len(data) - 1:
                lo, hi = data[i], data[i + 1]
                if hi == 0 and lo in set(string.printable.encode("ascii")) - {0x0b, 0x0c} and lo != 0:
                    current_chars.append(chr(lo))
                    i += 2
                else:
                    break
            if len(current_chars) >= min_length:
                s = "".join(current_chars).strip()
                if s:
                    results.append({
                        "offset": f"0x{start_offset:x}",
                        "encoding": "utf-16le",
                        "length": len(s),
                        "string": s,
                    })
            else:
                i += 1 if not current_chars else 0
            if not current_chars:
                i += 1

    results.sort(key=lambda x: int(x["offset"], 16))
    return results[:max_results]


# ═══════════════════════════════════════════════
# 3. XOR Encoder / Decoder
# ═══════════════════════════════════════════════

def xor_data(data: bytes, key: bytes) -> bytes:
    """XOR data with a repeating key."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def xor_brute_single_byte(data: bytes, min_printable_ratio: float = 0.75) -> list[dict]:
    """Brute-force single-byte XOR keys, ranking by printable character ratio."""
    printable = set(string.printable.encode("ascii"))
    results = []

    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        printable_count = sum(1 for b in decoded if b in printable)
        ratio = printable_count / len(decoded) if decoded else 0

        if ratio >= min_printable_ratio:
            preview = decoded[:80].decode("ascii", errors="replace")
            results.append({
                "key": f"0x{key:02x}",
                "key_char": chr(key) if 32 <= key < 127 else f"\\x{key:02x}",
                "printable_ratio": round(ratio, 4),
                "preview": preview,
            })

    results.sort(key=lambda x: -x["printable_ratio"])
    return results


# ═══════════════════════════════════════════════
# 4. Buffer Overflow Pattern (De Bruijn Sequence)
# ═══════════════════════════════════════════════

def _de_bruijn(charset: str, n: int = 4):
    """Generate a De Bruijn sequence for the given charset and subsequence length."""
    k = len(charset)
    a = [0] * k * n
    sequence: list[int] = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return "".join(charset[i] for i in sequence)


def pattern_create(length: int) -> str:
    """Create a cyclic pattern (De Bruijn sequence) for buffer overflow offset detection."""
    charset = string.ascii_uppercase + string.ascii_lowercase + string.digits
    pattern = _de_bruijn(charset, 4)
    # Extend pattern if needed
    while len(pattern) < length:
        pattern += pattern
    return pattern[:length]


def pattern_offset(value: str, length: int = 8192) -> Optional[int]:
    """Find the offset of a value within the cyclic pattern.

    Args:
        value: Hex value (e.g. "0x41386141") or ASCII string to search for.
        length: Length of cyclic pattern to generate.

    Returns:
        Offset position, or None if not found.
    """
    pattern = pattern_create(length)

    # Try as hex value (little-endian)
    if value.startswith("0x") or value.startswith("0X"):
        try:
            raw = bytes.fromhex(value[2:])
            # Try little-endian
            search_le = raw[::-1].decode("ascii", errors="replace")
            pos = pattern.find(search_le)
            if pos != -1:
                return pos
            # Try big-endian
            search_be = raw.decode("ascii", errors="replace")
            pos = pattern.find(search_be)
            if pos != -1:
                return pos
        except (ValueError, UnicodeDecodeError):
            pass

    # Try as raw ASCII
    pos = pattern.find(value)
    if pos != -1:
        return pos

    return None


# ═══════════════════════════════════════════════
# 5. Crypto Constant Detection
# ═══════════════════════════════════════════════

CRYPTO_SIGNATURES: list[dict] = [
    {
        "name": "AES S-Box",
        "pattern": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]),
        "description": "AES Forward S-Box (first 8 bytes)",
    },
    {
        "name": "AES Inverse S-Box",
        "pattern": bytes([0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38]),
        "description": "AES Inverse S-Box (first 8 bytes)",
    },
    {
        "name": "AES RCON",
        "pattern": bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]),
        "description": "AES Round Constants",
    },
    {
        "name": "SHA-256 Init (H0)",
        "pattern": bytes.fromhex("6a09e667"),
        "description": "SHA-256 initial hash value H0 (big-endian)",
    },
    {
        "name": "SHA-256 Init (H0 LE)",
        "pattern": bytes.fromhex("67e6096a"),
        "description": "SHA-256 initial hash value H0 (little-endian)",
    },
    {
        "name": "SHA-256 K[0]",
        "pattern": bytes.fromhex("428a2f98"),
        "description": "SHA-256 round constant K[0] (big-endian)",
    },
    {
        "name": "SHA-1 Init",
        "pattern": bytes.fromhex("67452301"),
        "description": "SHA-1 / MD5 initial hash value A (big-endian)",
    },
    {
        "name": "SHA-1 Init (LE)",
        "pattern": bytes.fromhex("01234567"),
        "description": "SHA-1 / MD5 initial hash value A (little-endian)",
    },
    {
        "name": "MD5 T[1]",
        "pattern": bytes.fromhex("d76aa478"),
        "description": "MD5 T table entry 1 (big-endian)",
    },
    {
        "name": "MD5 T[1] (LE)",
        "pattern": bytes.fromhex("78a46ad7"),
        "description": "MD5 T table entry 1 (little-endian)",
    },
    {
        "name": "DES Initial Permutation",
        "pattern": bytes([58, 50, 42, 34, 26, 18, 10, 2]),
        "description": "DES Initial Permutation Table (first 8 values)",
    },
    {
        "name": "RC4 Identity Permutation",
        "pattern": bytes(range(256)),
        "description": "RC4 S-Box initial identity permutation (0x00..0xFF)",
    },
    {
        "name": "Blowfish P[0]",
        "pattern": bytes.fromhex("243f6a88"),
        "description": "Blowfish P-array entry 0 (from pi digits)",
    },
    {
        "name": "Base64 Alphabet",
        "pattern": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "description": "Standard Base64 encoding alphabet",
    },
    {
        "name": "TEA/XTEA Delta",
        "pattern": bytes.fromhex("9e3779b9"),
        "description": "TEA/XTEA delta constant (golden ratio, big-endian)",
    },
    {
        "name": "TEA/XTEA Delta (LE)",
        "pattern": bytes.fromhex("b979379e"),
        "description": "TEA/XTEA delta constant (golden ratio, little-endian)",
    },
    {
        "name": "CRC32 Polynomial",
        "pattern": bytes.fromhex("edb88320"),
        "description": "CRC32 polynomial (reversed, little-endian)",
    },
    {
        "name": "Zlib Header",
        "pattern": bytes([0x78, 0x9c]),
        "description": "Zlib default compression header",
    },
    {
        "name": "Zlib Header (best)",
        "pattern": bytes([0x78, 0xda]),
        "description": "Zlib best compression header",
    },
    {
        "name": "PK Zip Signature",
        "pattern": b"PK\x03\x04",
        "description": "PK Zip local file header signature",
    },
    {
        "name": "ELF Magic",
        "pattern": b"\x7fELF",
        "description": "ELF file magic number",
    },
    {
        "name": "PNG Signature",
        "pattern": bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        "description": "PNG file signature",
    },
]


def detect_crypto_constants(data: bytes) -> list[dict]:
    """Scan binary data for known cryptographic and encoding constants."""
    results = []
    for sig in CRYPTO_SIGNATURES:
        pattern = sig["pattern"]
        offset = 0
        while True:
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            results.append({
                "name": sig["name"],
                "offset": f"0x{pos:x}",
                "description": sig["description"],
                "matched_bytes": pattern[:16].hex(),
            })
            offset = pos + 1
    results.sort(key=lambda x: int(x["offset"], 16))
    return results


# ═══════════════════════════════════════════════
# 6. Shellcode Analysis
# ═══════════════════════════════════════════════

SHELLCODE_PATTERNS = [
    {
        "name": "NOP Sled (x86)",
        "pattern": re.compile(b"\x90{8,}"),
        "description": "NOP sled (8+ consecutive 0x90 bytes)",
    },
    {
        "name": "INT 0x80 (Linux x86 syscall)",
        "pattern": re.compile(b"\xcd\x80"),
        "description": "Linux x86 system call via INT 0x80",
    },
    {
        "name": "SYSCALL (x86_64)",
        "pattern": re.compile(b"\x0f\x05"),
        "description": "Linux x86_64 system call via SYSCALL instruction",
    },
    {
        "name": "SYSENTER (x86)",
        "pattern": re.compile(b"\x0f\x34"),
        "description": "x86 fast system call via SYSENTER",
    },
    {
        "name": "/bin/sh string",
        "pattern": re.compile(b"/bin/sh"),
        "description": "Shell path string (common in shellcode)",
    },
    {
        "name": "/bin/bash string",
        "pattern": re.compile(b"/bin/bash"),
        "description": "Bash path string",
    },
    {
        "name": "XOR self-decode (x86)",
        "pattern": re.compile(b"\x80\x34..", re.DOTALL),  # xor byte [esi+N], key
        "description": "Potential XOR self-decoding loop",
    },
    {
        "name": "Stack pivot (xchg eax, esp)",
        "pattern": re.compile(b"\x94"),
        "description": "xchg eax, esp - potential stack pivot",
    },
    {
        "name": "JMP ESP (x86)",
        "pattern": re.compile(b"\xff\xe4"),
        "description": "jmp esp - classic shellcode redirect",
    },
    {
        "name": "CALL ESP (x86)",
        "pattern": re.compile(b"\xff\xd4"),
        "description": "call esp - shellcode redirect variant",
    },
    {
        "name": "JMP EAX (x86)",
        "pattern": re.compile(b"\xff\xe0"),
        "description": "jmp eax",
    },
    {
        "name": "CALL EAX (x86)",
        "pattern": re.compile(b"\xff\xd0"),
        "description": "call eax",
    },
    {
        "name": "Push-Ret (x86)",
        "pattern": re.compile(b"\x68.{4}\xc3"),
        "description": "push <addr>; ret - indirect jump via stack",
    },
]


def detect_shellcode_patterns(data: bytes) -> list[dict]:
    """Scan binary data for common shellcode patterns and indicators."""
    results = []
    for sp in SHELLCODE_PATTERNS:
        for match in sp["pattern"].finditer(data):
            results.append({
                "name": sp["name"],
                "offset": f"0x{match.start():x}",
                "size": match.end() - match.start(),
                "matched_hex": data[match.start():match.end()][:16].hex(),
                "description": sp["description"],
            })
    results.sort(key=lambda x: int(x["offset"], 16))
    return results


def analyze_shellcode(
    code: bytes,
    arch: ArchType,
    base_address: int = 0,
) -> dict:
    """Comprehensive shellcode analysis: disassemble + pattern detection + stats."""
    from .disassembler import disassemble

    instructions = disassemble(code, arch, base_address)
    patterns = detect_shellcode_patterns(code)

    # Instruction statistics
    mnemonic_counts: dict[str, int] = {}
    syscalls = []
    stack_ops = []
    register_writes: dict[str, list[str]] = {}

    for inst in instructions:
        mnemonic_counts[inst.mnemonic] = mnemonic_counts.get(inst.mnemonic, 0) + 1

        if inst.mnemonic in ("int", "syscall", "sysenter"):
            syscalls.append(f"0x{inst.address:x}: {inst.mnemonic} {inst.op_str}")
        if inst.mnemonic in ("push", "pop", "pushad", "popad", "pusha", "popa"):
            stack_ops.append(f"0x{inst.address:x}: {inst.mnemonic} {inst.op_str}")

    # Null byte detection
    null_count = code.count(b"\x00")
    null_free = null_count == 0

    return {
        "size": len(code),
        "total_instructions": len(instructions),
        "null_bytes": null_count,
        "null_free": null_free,
        "detected_patterns": patterns,
        "syscalls": syscalls,
        "stack_operations_count": len(stack_ops),
        "top_mnemonics": dict(sorted(mnemonic_counts.items(), key=lambda x: -x[1])[:15]),
        "disassembly": [inst.to_asm_line() for inst in instructions],
    }
