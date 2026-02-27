"""Capstone MCP Server - Disassembly tooling service for LLM integration."""

import json
import os
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .disassembler import (
    ArchType,
    analyze_control_flow,
    disassemble,
    disassemble_to_text,
    find_xrefs,
    get_supported_architectures,
    search_pattern,
)
from .binary_parser import (
    parse_binary,
    read_bytes_at_offset,
    read_bytes_at_va,
    read_section_bytes,
)
from .ctf_utils import (
    find_rop_gadgets,
    extract_strings,
    xor_data,
    xor_brute_single_byte,
    pattern_create,
    pattern_offset,
    detect_crypto_constants,
    detect_shellcode_patterns,
    analyze_shellcode,
)
from .security import (
    checksec,
    analyze_plt_got,
    analyze_iat,
    hex_dump,
)
from .syscall import (
    lookup_syscall,
    lookup_syscall_by_name,
    list_all_syscalls,
    get_available_platforms,
)

mcp = FastMCP("Capstone Disassembly Server")


# ──────────────────────────────────────────────
# Tool 1: List Supported Architectures
# ──────────────────────────────────────────────
@mcp.tool()
def list_supported_architectures() -> str:
    """List all supported CPU architectures.

    Returns available architecture identifiers for the 'arch' parameter used by disassemble_hex, disassemble_file_section, etc.
    """
    archs = get_supported_architectures()
    lines = ["Supported Architectures:", ""]
    for a in archs:
        lines.append(f"  {a['arch']:<14s}  {a['description']}")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 2: Disassemble Hex Bytes
# ──────────────────────────────────────────────
@mcp.tool()
def disassemble_hex(
    hex_code: str,
    arch: str = "x86_64",
    base_address: str = "0",
    max_instructions: int = 0,
) -> str:
    """Disassemble a hex-encoded byte string into assembly code.

    Args:
        hex_code: Hex-encoded machine code bytes, e.g. "554889e5" or "55 48 89 e5" (spaces are auto-stripped).
        arch: CPU architecture. Use list_supported_architectures to see available values. Default: x86_64.
        base_address: Base address as a hex string (e.g. "0x401000"). Default: "0".
        max_instructions: Maximum number of instructions to disassemble. 0 means unlimited.

    Returns:
        Formatted disassembly output with address, bytes, mnemonic and operands.
    """
    try:
        arch_type = ArchType(arch)
    except ValueError:
        valid = [a.value for a in ArchType]
        return f"Error: Unsupported architecture '{arch}'. Available: {valid}"

    cleaned = hex_code.replace(" ", "").replace("\n", "").replace("\\x", "")
    try:
        code_bytes = bytes.fromhex(cleaned)
    except ValueError as e:
        return f"Error: Invalid hex string - {e}"

    base = int(base_address, 0)
    result = disassemble_to_text(code_bytes, arch_type, base, max_instructions)

    header = (
        f"Architecture: {arch}\n"
        f"Base Address: 0x{base:x}\n"
        f"Input Size:   {len(code_bytes)} bytes\n"
        f"{'─' * 60}\n"
    )
    return header + result


# ──────────────────────────────────────────────
# Tool 3: Disassemble File Section
# ──────────────────────────────────────────────
@mcp.tool()
def disassemble_file_section(
    file_path: str,
    section_name: str = ".text",
    arch: Optional[str] = None,
    max_instructions: int = 200,
) -> str:
    """Disassemble a named section from a binary file (PE/ELF/Mach-O).

    Args:
        file_path: Absolute path to the binary file.
        section_name: Section name to disassemble. Default: ".text".
        arch: CPU architecture. Auto-detected from file header if omitted.
        max_instructions: Maximum instructions to disassemble. Default: 200. Set 0 for unlimited.

    Returns:
        Disassembly output for the section, including file metadata.
    """
    try:
        info = parse_binary(file_path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    arch_type = None
    if arch:
        try:
            arch_type = ArchType(arch)
        except ValueError:
            return f"Error: Unsupported architecture '{arch}'."
    else:
        arch_type = info.detected_arch
        if arch_type is None:
            return (
                f"Error: Cannot auto-detect architecture. Please specify the 'arch' parameter.\n"
                f"File format: {info.format}, Architecture field: {info.arch}"
            )

    try:
        code_bytes, va = read_section_bytes(file_path, section_name)
    except ValueError as e:
        return f"Error: {e}"

    if not code_bytes:
        return f"Section '{section_name}' is empty."

    result = disassemble_to_text(code_bytes, arch_type, va, max_instructions)

    header = (
        f"File:         {os.path.basename(file_path)}\n"
        f"Format:       {info.format}\n"
        f"Architecture: {arch_type.value} ({'auto-detected' if not arch else 'manual'})\n"
        f"Section:      {section_name}\n"
        f"VA Range:     0x{va:x} - 0x{va + len(code_bytes):x}\n"
        f"Section Size: {len(code_bytes)} bytes\n"
        f"Max Instrs:   {max_instructions if max_instructions else 'unlimited'}\n"
        f"{'─' * 60}\n"
    )
    return header + result


# ──────────────────────────────────────────────
# Tool 4: Disassemble at Virtual Address
# ──────────────────────────────────────────────
@mcp.tool()
def disassemble_at_address(
    file_path: str,
    virtual_address: str,
    size: int = 256,
    arch: Optional[str] = None,
    max_instructions: int = 50,
) -> str:
    """Disassemble code at a specific virtual address in a binary file.

    Args:
        file_path: Absolute path to the binary file.
        virtual_address: Starting virtual address as hex string (e.g. "0x401000").
        size: Number of bytes to read. Default: 256.
        arch: CPU architecture. Auto-detected if omitted.
        max_instructions: Maximum instructions to disassemble. Default: 50.

    Returns:
        Disassembly output at the specified address.
    """
    try:
        info = parse_binary(file_path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    arch_type = None
    if arch:
        try:
            arch_type = ArchType(arch)
        except ValueError:
            return f"Error: Unsupported architecture '{arch}'."
    else:
        arch_type = info.detected_arch
        if arch_type is None:
            return "Error: Cannot auto-detect architecture. Please specify the 'arch' parameter."

    va = int(virtual_address, 0)
    try:
        code_bytes, _ = read_bytes_at_va(file_path, va, size)
    except Exception as e:
        return f"Error: Cannot read data at address 0x{va:x} - {e}"

    result = disassemble_to_text(code_bytes, arch_type, va, max_instructions)
    header = (
        f"File:         {os.path.basename(file_path)}\n"
        f"Address:      0x{va:x}\n"
        f"Read Size:    {len(code_bytes)} bytes\n"
        f"Architecture: {arch_type.value}\n"
        f"{'─' * 60}\n"
    )
    return header + result


# ──────────────────────────────────────────────
# Tool 5: Get Binary File Info
# ──────────────────────────────────────────────
@mcp.tool()
def get_binary_info(file_path: str) -> str:
    """Get detailed metadata of a binary file (PE/ELF/Mach-O).

    Includes file format, architecture, entrypoint, section list, imports/exports, etc.

    Args:
        file_path: Absolute path to the binary file.

    Returns:
        File metadata in JSON format.
    """
    try:
        info = parse_binary(file_path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    return json.dumps(info.to_dict(), indent=2, ensure_ascii=False)


# ──────────────────────────────────────────────
# Tool 6: Search Instructions
# ──────────────────────────────────────────────
@mcp.tool()
def search_instructions(
    hex_code: str,
    arch: str = "x86_64",
    base_address: str = "0",
    mnemonic: Optional[str] = None,
    group: Optional[str] = None,
) -> str:
    """Search for instructions matching a specific pattern in disassembled code.

    Filter by mnemonic name or instruction group (call/jump/ret/interrupt).

    Args:
        hex_code: Hex-encoded machine code bytes.
        arch: CPU architecture. Default: x86_64.
        base_address: Base address. Default: "0".
        mnemonic: Mnemonic to search for (partial match), e.g. "mov", "call", "push".
        group: Instruction group to filter: call, jump, ret, interrupt.

    Returns:
        List of matching instructions.
    """
    if not mnemonic and not group:
        return "Error: Please specify at least one of 'mnemonic' or 'group'."

    try:
        arch_type = ArchType(arch)
    except ValueError:
        return f"Error: Unsupported architecture '{arch}'."

    cleaned = hex_code.replace(" ", "").replace("\n", "").replace("\\x", "")
    try:
        code_bytes = bytes.fromhex(cleaned)
    except ValueError as e:
        return f"Error: Invalid hex string - {e}"

    base = int(base_address, 0)
    results = search_pattern(code_bytes, arch_type, base, mnemonic, group)

    if not results:
        return "No matching instructions found."

    lines = [f"Found {len(results)} matching instruction(s):", ""]
    for inst in results:
        lines.append(inst.to_asm_line())
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 7: Search Instructions in File
# ──────────────────────────────────────────────
@mcp.tool()
def search_instructions_in_file(
    file_path: str,
    section_name: str = ".text",
    arch: Optional[str] = None,
    mnemonic: Optional[str] = None,
    group: Optional[str] = None,
) -> str:
    """Search for instructions matching a pattern in a binary file's section.

    Args:
        file_path: Absolute path to the binary file.
        section_name: Section name. Default: ".text".
        arch: CPU architecture. Auto-detected if omitted.
        mnemonic: Mnemonic to search for (partial match).
        group: Instruction group to filter: call, jump, ret, interrupt.

    Returns:
        List of matching instructions.
    """
    if not mnemonic and not group:
        return "Error: Please specify at least one of 'mnemonic' or 'group'."

    try:
        info = parse_binary(file_path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    arch_type = None
    if arch:
        try:
            arch_type = ArchType(arch)
        except ValueError:
            return f"Error: Unsupported architecture '{arch}'."
    else:
        arch_type = info.detected_arch
        if arch_type is None:
            return "Error: Cannot auto-detect architecture. Please specify the 'arch' parameter."

    try:
        code_bytes, va = read_section_bytes(file_path, section_name)
    except ValueError as e:
        return f"Error: {e}"

    results = search_pattern(code_bytes, arch_type, va, mnemonic, group)

    if not results:
        return "No matching instructions found."

    lines = [
        f"File: {os.path.basename(file_path)}",
        f"Section: {section_name}",
        f"Found {len(results)} matching instruction(s):",
        "",
    ]
    for inst in results[:200]:  # limit output
        lines.append(inst.to_asm_line())
    if len(results) > 200:
        lines.append(f"\n... and {len(results) - 200} more results (truncated)")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 8: Control Flow Analysis
# ──────────────────────────────────────────────
@mcp.tool()
def analyze_code_flow(
    hex_code: str,
    arch: str = "x86_64",
    base_address: str = "0",
) -> str:
    """Perform control flow analysis on machine code, identifying basic blocks, jumps, calls and returns.

    Args:
        hex_code: Hex-encoded machine code bytes.
        arch: CPU architecture. Default: x86_64.
        base_address: Base address. Default: "0".

    Returns:
        JSON-formatted control flow analysis with basic blocks, edges, calls and return info.
    """
    try:
        arch_type = ArchType(arch)
    except ValueError:
        return f"Error: Unsupported architecture '{arch}'."

    cleaned = hex_code.replace(" ", "").replace("\n", "").replace("\\x", "")
    try:
        code_bytes = bytes.fromhex(cleaned)
    except ValueError as e:
        return f"Error: Invalid hex string - {e}"

    base = int(base_address, 0)
    result = analyze_control_flow(code_bytes, arch_type, base)
    return json.dumps(result, indent=2, ensure_ascii=False)


# ──────────────────────────────────────────────
# Tool 9a: Cross-Reference Search (Hex)
# ──────────────────────────────────────────────
@mcp.tool()
def find_xrefs_hex(
    hex_code: str,
    target_address: str,
    arch: str = "x86_64",
    base_address: str = "0",
) -> str:
    """Find all cross-references to a target address in hex-encoded machine code.

    Searches for call, jump, immediate value, and memory displacement references
    to the specified target address.

    Args:
        hex_code: Hex-encoded machine code bytes.
        target_address: Target address to find references to (hex string, e.g. "0x401000").
        arch: CPU architecture. Default: x86_64.
        base_address: Base address. Default: "0".

    Returns:
        List of cross-references with source address, type, and instruction.
    """
    try:
        arch_type = ArchType(arch)
    except ValueError:
        return f"Error: Unsupported architecture '{arch}'."

    cleaned = hex_code.replace(" ", "").replace("\n", "").replace("\\x", "")
    try:
        code_bytes = bytes.fromhex(cleaned)
    except ValueError as e:
        return f"Error: Invalid hex string - {e}"

    base = int(base_address, 0)
    target = int(target_address, 0)
    xrefs = find_xrefs(code_bytes, arch_type, base, target)

    if not xrefs:
        return f"No cross-references found to 0x{target:x}."

    lines = [f"Found {len(xrefs)} cross-reference(s) to 0x{target:x}:", ""]
    for x in xrefs:
        lines.append(f"  {x['from']}  [{x['type']:<14s}]  {x['instruction']}")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 9b: Cross-Reference Search (File)
# ──────────────────────────────────────────────
@mcp.tool()
def find_xrefs_in_file(
    file_path: str,
    target_address: str,
    section_name: str = ".text",
    arch: Optional[str] = None,
) -> str:
    """Find all cross-references to a target address in a binary file's section.

    Scans the specified section for all instructions that reference the target
    address via call, jump, immediate operand, or memory displacement.

    Args:
        file_path: Absolute path to the binary file.
        target_address: Target address to find references to (hex string, e.g. "0x401000").
        section_name: Section to scan. Default: ".text".
        arch: CPU architecture. Auto-detected if omitted.

    Returns:
        List of cross-references with source address, type, and instruction.
    """
    try:
        info = parse_binary(file_path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    arch_type = None
    if arch:
        try:
            arch_type = ArchType(arch)
        except ValueError:
            return f"Error: Unsupported architecture '{arch}'."
    else:
        arch_type = info.detected_arch
        if arch_type is None:
            return "Error: Cannot auto-detect architecture. Please specify the 'arch' parameter."

    try:
        code_bytes, va = read_section_bytes(file_path, section_name)
    except ValueError as e:
        return f"Error: {e}"

    target = int(target_address, 0)
    xrefs = find_xrefs(code_bytes, arch_type, va, target)

    if not xrefs:
        return f"No cross-references found to 0x{target:x} in section '{section_name}'."

    lines = [
        f"File: {os.path.basename(file_path)}",
        f"Section: {section_name}",
        f"Target: 0x{target:x}",
        f"Found {len(xrefs)} cross-reference(s):",
        "",
    ]
    for x in xrefs:
        lines.append(f"  {x['from']}  [{x['type']:<14s}]  {x['instruction']}")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 10: Disassemble Entrypoint
# ──────────────────────────────────────────────
@mcp.tool()
def disassemble_entrypoint(
    file_path: str,
    size: int = 512,
    arch: Optional[str] = None,
    max_instructions: int = 100,
) -> str:
    """Disassemble code at the binary file's entrypoint.

    Automatically locates the entrypoint address and disassembles from there.

    Args:
        file_path: Absolute path to the binary file.
        size: Number of bytes to read from the entrypoint. Default: 512.
        arch: CPU architecture. Auto-detected if omitted.
        max_instructions: Maximum instructions to disassemble. Default: 100.

    Returns:
        Disassembly output at the entrypoint.
    """
    try:
        info = parse_binary(file_path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    arch_type = None
    if arch:
        try:
            arch_type = ArchType(arch)
        except ValueError:
            return f"Error: Unsupported architecture '{arch}'."
    else:
        arch_type = info.detected_arch
        if arch_type is None:
            return "Error: Cannot auto-detect architecture. Please specify the 'arch' parameter."

    ep = info.entrypoint
    try:
        code_bytes, _ = read_bytes_at_va(file_path, ep, size)
    except Exception as e:
        return f"Error: Cannot read data at entrypoint 0x{ep:x} - {e}"

    result = disassemble_to_text(code_bytes, arch_type, ep, max_instructions)
    header = (
        f"File:         {os.path.basename(file_path)}\n"
        f"Format:       {info.format}\n"
        f"Architecture: {arch_type.value}\n"
        f"Entrypoint:   0x{ep:x}\n"
        f"Read Size:    {len(code_bytes)} bytes\n"
        f"{'─' * 60}\n"
    )
    return header + result


# ──────────────────────────────────────────────
# Tool 10: Disassemble at Raw File Offset
# ──────────────────────────────────────────────
@mcp.tool()
def disassemble_raw_offset(
    file_path: str,
    offset: str,
    size: int = 256,
    arch: str = "x86_64",
    base_address: Optional[str] = None,
    max_instructions: int = 50,
) -> str:
    """Read raw bytes at a file offset and disassemble them.

    Unlike disassemble_at_address, this uses a raw file offset instead of a virtual address.

    Args:
        file_path: Absolute path to the file (any file, not limited to PE/ELF).
        offset: File offset as hex string (e.g. "0x400").
        size: Number of bytes to read. Default: 256.
        arch: CPU architecture. Default: x86_64.
        base_address: Display base address for disassembly. Defaults to offset value.
        max_instructions: Maximum instructions to disassemble. Default: 50.

    Returns:
        Disassembly output at the file offset.
    """
    try:
        arch_type = ArchType(arch)
    except ValueError:
        return f"Error: Unsupported architecture '{arch}'."

    off = int(offset, 0)
    base = int(base_address, 0) if base_address else off

    try:
        code_bytes = read_bytes_at_offset(file_path, off, size)
    except Exception as e:
        return f"Error: {e}"

    if not code_bytes:
        return f"No data at offset 0x{off:x}."

    result = disassemble_to_text(code_bytes, arch_type, base, max_instructions)
    header = (
        f"File:         {os.path.basename(file_path)}\n"
        f"File Offset:  0x{off:x}\n"
        f"Base Address: 0x{base:x}\n"
        f"Read Size:    {len(code_bytes)} bytes\n"
        f"Architecture: {arch_type.value}\n"
        f"{'─' * 60}\n"
    )
    return header + result


# ══════════════════════════════════════════════
# CTF / Reverse Engineering Tools
# ══════════════════════════════════════════════


# ──────────────────────────────────────────────
# Tool 11: ROP Gadget Search (Hex)
# ──────────────────────────────────────────────
@mcp.tool()
def find_rop_gadgets_hex(
    hex_code: str,
    arch: str = "x86_64",
    base_address: str = "0",
    max_gadget_len: int = 5,
    max_results: int = 100,
) -> str:
    """Search for ROP gadgets (instruction sequences ending with ret) in hex-encoded machine code.

    Used for ROP chain construction in CTF Pwn challenges.

    Args:
        hex_code: Hex-encoded machine code bytes.
        arch: CPU architecture. Default: x86_64.
        base_address: Base address. Default: "0".
        max_gadget_len: Maximum number of instructions per gadget. Default: 5.
        max_results: Maximum number of results to return. Default: 100.

    Returns:
        List of ROP gadgets with addresses and instruction sequences.
    """
    try:
        arch_type = ArchType(arch)
    except ValueError:
        return f"Error: Unsupported architecture '{arch}'."

    cleaned = hex_code.replace(" ", "").replace("\n", "").replace("\\x", "")
    try:
        code_bytes = bytes.fromhex(cleaned)
    except ValueError as e:
        return f"Error: Invalid hex string - {e}"

    base = int(base_address, 0)
    gadgets = find_rop_gadgets(code_bytes, arch_type, base, max_gadget_len, max_results)

    if not gadgets:
        return "No ROP gadgets found."

    lines = [f"Found {len(gadgets)} ROP gadget(s):", ""]
    for g in gadgets:
        lines.append(f"  {g['address']}:  {g['gadget']}")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 12: ROP Gadget Search (File)
# ──────────────────────────────────────────────
@mcp.tool()
def find_rop_gadgets_in_file(
    file_path: str,
    section_name: str = ".text",
    arch: Optional[str] = None,
    max_gadget_len: int = 5,
    max_results: int = 100,
) -> str:
    """Search for ROP gadgets in a binary file's section.

    Args:
        file_path: Absolute path to the binary file.
        section_name: Section name. Default: ".text".
        arch: CPU architecture. Auto-detected if omitted.
        max_gadget_len: Maximum instructions per gadget. Default: 5.
        max_results: Maximum results to return. Default: 100.

    Returns:
        List of ROP gadgets found.
    """
    try:
        info = parse_binary(file_path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    arch_type = None
    if arch:
        try:
            arch_type = ArchType(arch)
        except ValueError:
            return f"Error: Unsupported architecture '{arch}'."
    else:
        arch_type = info.detected_arch
        if arch_type is None:
            return "Error: Cannot auto-detect architecture. Please specify the 'arch' parameter."

    try:
        code_bytes, va = read_section_bytes(file_path, section_name)
    except ValueError as e:
        return f"Error: {e}"

    gadgets = find_rop_gadgets(code_bytes, arch_type, va, max_gadget_len, max_results)

    if not gadgets:
        return "No ROP gadgets found."

    lines = [
        f"File: {os.path.basename(file_path)}",
        f"Section: {section_name}",
        f"Found {len(gadgets)} ROP gadget(s):",
        "",
    ]
    for g in gadgets:
        lines.append(f"  {g['address']}:  {g['gadget']}")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 13: String Extraction
# ──────────────────────────────────────────────
@mcp.tool()
def extract_strings_from_file(
    file_path: str,
    min_length: int = 4,
    encoding: str = "both",
    max_results: int = 300,
) -> str:
    """Extract readable strings from a binary file (similar to the `strings` command).

    Args:
        file_path: Absolute path to the file.
        min_length: Minimum string length. Default: 4.
        encoding: Encoding type: "ascii", "utf16le", or "both" (default).
        max_results: Maximum results to return. Default: 300.

    Returns:
        List of extracted strings with offset and encoding info.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"Error: {e}"

    strings = extract_strings(data, min_length, encoding, max_results)

    if not strings:
        return "No matching strings found."

    lines = [
        f"File: {os.path.basename(file_path)}",
        f"Total strings found: {len(strings)}",
        "",
    ]
    for s in strings:
        lines.append(f"  {s['offset']}  [{s['encoding']:>7s}]  {s['string']}")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 14: XOR Brute Force
# ──────────────────────────────────────────────
@mcp.tool()
def xor_brute_force(
    hex_data: str,
    min_printable_ratio: float = 0.75,
) -> str:
    """Brute-force single-byte XOR decryption, ranked by printable character ratio.

    Commonly used in CTF to decrypt simple XOR-encrypted flags or strings.

    Args:
        hex_data: Hex-encoded ciphertext data.
        min_printable_ratio: Minimum printable character ratio threshold. Default: 0.75.

    Returns:
        Candidate decryption results sorted by printable ratio.
    """
    cleaned = hex_data.replace(" ", "").replace("\n", "").replace("\\x", "")
    try:
        data = bytes.fromhex(cleaned)
    except ValueError as e:
        return f"Error: Invalid hex string - {e}"

    results = xor_brute_single_byte(data, min_printable_ratio)

    if not results:
        return f"No results with printable ratio >= {min_printable_ratio}."

    lines = [f"Found {len(results)} candidate(s):", ""]
    for r in results:
        lines.append(
            f"  Key: {r['key']} ({r['key_char']})  "
            f"Printable: {r['printable_ratio']:.1%}  "
            f"Preview: {r['preview']}"
        )
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 15: XOR Encode/Decode
# ──────────────────────────────────────────────
@mcp.tool()
def xor_encode_decode(
    hex_data: str,
    hex_key: str,
) -> str:
    """XOR encode/decode data with a specified key.

    Args:
        hex_data: Hex-encoded data.
        hex_key: Hex-encoded key (supports multi-byte keys, applied cyclically).

    Returns:
        XOR result as hex output with ASCII preview.
    """
    try:
        data = bytes.fromhex(hex_data.replace(" ", "").replace("\\x", ""))
        key = bytes.fromhex(hex_key.replace(" ", "").replace("\\x", ""))
    except ValueError as e:
        return f"Error: Invalid hex string - {e}"

    if not key:
        return "Error: Key cannot be empty."

    result = xor_data(data, key)
    hex_result = result.hex()
    ascii_preview = result.decode("ascii", errors="replace")

    return (
        f"Input:  {hex_data}\n"
        f"Key:    {hex_key}\n"
        f"Output: {hex_result}\n"
        f"ASCII:  {ascii_preview}\n"
    )


# ──────────────────────────────────────────────
# Tool 16: Buffer Overflow Pattern
# ──────────────────────────────────────────────
@mcp.tool()
def buffer_overflow_pattern(
    action: str,
    value: str = "",
    length: int = 200,
) -> str:
    """Generate or find offset in a cyclic buffer overflow pattern (De Bruijn sequence).

    Used to determine the exact EIP/RIP overwrite offset. Similar to Metasploit's pattern_create / pattern_offset.

    Args:
        action: "create" to generate a pattern, "offset" to find an offset.
        value: When action="offset", the value to search for (hex like "0x41386141" or ASCII string).
        length: When action="create", pattern length (default 200). When action="offset", search range.

    Returns:
        Generated pattern or offset lookup result.
    """
    if action == "create":
        if length > 50000:
            return "Error: Pattern length cannot exceed 50000."
        pat = pattern_create(length)
        return f"Pattern (length={length}):\n{pat}"

    elif action == "offset":
        if not value:
            return "Error: 'value' parameter is required when action='offset'."
        offset = pattern_offset(value, max(length, 8192))
        if offset is not None:
            return f"Value:  {value}\nOffset: {offset} (0x{offset:x})"
        else:
            return f"Value '{value}' not found in pattern (length={max(length, 8192)})."

    else:
        return "Error: 'action' must be 'create' or 'offset'."


# ──────────────────────────────────────────────
# Tool 17: Checksec
# ──────────────────────────────────────────────
@mcp.tool()
def check_security(file_path: str) -> str:
    """Check security features of a binary file (similar to the checksec tool).

    ELF: NX, PIE, RELRO, Stack Canary, FORTIFY, RPATH, Stripped
    PE:  DEP/NX, ASLR, SEH, CFG, Authenticode
    Mach-O: PIE, Stack Canary, Code Signing

    Args:
        file_path: Absolute path to the binary file.

    Returns:
        Security feature detection results.
    """
    try:
        result = checksec(file_path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    lines = [f"Security Check: {result.pop('file')}", f"Format: {result.pop('format')}", ""]
    for key, val in result.items():
        indicator = "✓" if any(k in str(val).lower() for k in ("enabled", "found", "full", "yes", "signed")) else "✗"
        lines.append(f"  [{indicator}] {key:<20s} {val}")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 18: PLT/GOT & IAT Analysis
# ──────────────────────────────────────────────
@mcp.tool()
def analyze_plt_got_table(file_path: str) -> str:
    """Analyze PLT/GOT tables (ELF) or IAT (PE) of a binary file.

    PLT/GOT is the core of ELF dynamic linking and the target of GOT overwrite attacks.
    IAT is the PE Import Address Table, commonly used for hooking and patching.

    Args:
        file_path: Absolute path to the binary file.

    Returns:
        PLT/GOT or IAT analysis results in JSON format.
    """
    try:
        info = parse_binary(file_path)
    except (FileNotFoundError, ValueError) as e:
        return f"Error: {e}"

    try:
        if info.format == "PE":
            result = analyze_iat(file_path)
        else:
            result = analyze_plt_got(file_path)
    except Exception as e:
        return f"Error: {e}"

    return json.dumps(result, indent=2, ensure_ascii=False)


# ──────────────────────────────────────────────
# Tool 19: Hex Dump
# ──────────────────────────────────────────────
@mcp.tool()
def hex_dump_file(
    file_path: str,
    offset: str = "0",
    length: int = 256,
) -> str:
    """View file contents as a formatted hex dump.

    Args:
        file_path: Absolute path to the file.
        offset: Starting file offset as hex string. Default: "0".
        length: Number of bytes to display. Default: 256. Max: 4096.

    Returns:
        Formatted hex dump with address, hex values, and ASCII display.
    """
    off = int(offset, 0)
    length = min(length, 4096)

    try:
        data = read_bytes_at_offset(file_path, off, length)
    except Exception as e:
        return f"Error: {e}"

    if not data:
        return f"No data at offset 0x{off:x}."

    sep = "─" * 76
    header = (
        f"File:   {os.path.basename(file_path)}\n"
        f"Offset: 0x{off:x}\n"
        f"Length: {len(data)} bytes\n"
        f"{sep}\n"
    )
    return header + hex_dump(data, off, length)


# ──────────────────────────────────────────────
# Tool 20: Crypto Constant Detection
# ──────────────────────────────────────────────
@mcp.tool()
def detect_crypto_in_file(file_path: str) -> str:
    """Scan a binary file for known cryptographic algorithm constants and signatures.

    Detects: AES S-Box, SHA-256, SHA-1, MD5, DES, RC4, Blowfish, TEA/XTEA, CRC32,
    Base64 alphabet, and common file format signatures.

    Args:
        file_path: Absolute path to the file.

    Returns:
        List of detected crypto constants.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"Error: {e}"

    results = detect_crypto_constants(data)

    if not results:
        return "No known crypto constants detected."

    lines = [
        f"File: {os.path.basename(file_path)}",
        f"Detected {len(results)} crypto constant(s):",
        "",
    ]
    for r in results:
        lines.append(f"  {r['offset']}  {r['name']:<24s}  {r['description']}")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 21: Shellcode Analysis
# ──────────────────────────────────────────────
@mcp.tool()
def analyze_shellcode_hex(
    hex_code: str,
    arch: str = "x86_64",
    base_address: str = "0",
) -> str:
    """Comprehensively analyze shellcode: disassembly + pattern detection + statistics.

    Detects NOP sleds, syscalls, common shellcode jump patterns, null bytes, etc.

    Args:
        hex_code: Hex-encoded shellcode.
        arch: CPU architecture. Default: x86_64.
        base_address: Base address. Default: "0".

    Returns:
        JSON-formatted shellcode analysis results.
    """
    try:
        arch_type = ArchType(arch)
    except ValueError:
        return f"Error: Unsupported architecture '{arch}'."

    cleaned = hex_code.replace(" ", "").replace("\n", "").replace("\\x", "")
    try:
        code_bytes = bytes.fromhex(cleaned)
    except ValueError as e:
        return f"Error: Invalid hex string - {e}"

    base = int(base_address, 0)
    result = analyze_shellcode(code_bytes, arch_type, base)
    return json.dumps(result, indent=2, ensure_ascii=False)


# ──────────────────────────────────────────────
# Tool 22: Syscall Lookup
# ──────────────────────────────────────────────
@mcp.tool()
def syscall_lookup(
    query: str,
    platform: str = "x86_64",
) -> str:
    """Look up Linux system call information.

    Supports lookup by number or name (partial match).

    Args:
        query: Syscall number (e.g. "59") or name (e.g. "execve", supports partial match).
        platform: Platform: x86, x86_64/x64, arm/arm32, arm64/aarch64. Default: x86_64.

    Returns:
        Matching syscall info including number, name, and arguments.
    """
    platforms = get_available_platforms()
    if platform.lower() not in platforms:
        return f"Error: Unsupported platform '{platform}'. Available: {platforms}"

    # Try as number first
    try:
        num = int(query, 0)
        result = lookup_syscall(num, platform)
        if result:
            return (
                f"Syscall #{result['number']} ({result['platform']})\n"
                f"  Name: {result['name']}\n"
                f"  Args: {result['args']}"
            )
        else:
            return f"No syscall found with number {num} (platform={platform})."
    except ValueError:
        pass

    # Search by name
    results = lookup_syscall_by_name(query, platform)
    if not results:
        return f"No syscall found matching '{query}' (platform={platform})."

    lines = [f"Found {len(results)} syscall(s) matching '{query}' ({platform}):", ""]
    for r in results:
        lines.append(f"  #{r['number']:<4d}  {r['name']:<20s}  args: {r['args']}")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 23: List All Syscalls
# ──────────────────────────────────────────────
@mcp.tool()
def syscall_list(platform: str = "x86_64") -> str:
    """List all system calls for a given platform.

    Args:
        platform: Platform: x86, x86_64/x64, arm/arm32, arm64/aarch64. Default: x86_64.

    Returns:
        Complete syscall table for the platform.
    """
    platforms = get_available_platforms()
    if platform.lower() not in platforms:
        return f"Error: Unsupported platform '{platform}'. Available: {platforms}"

    syscalls = list_all_syscalls(platform)
    if not syscalls:
        return f"No syscall table available for platform '{platform}'."

    lines = [f"Linux {platform} Syscall Table ({len(syscalls)} entries):", ""]
    for s in syscalls:
        lines.append(f"  #{s['number']:<4d}  {s['name']:<20s}  args: {s['args']}")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Resource: Architecture Reference
# ──────────────────────────────────────────────
@mcp.resource("capstone://architectures")
def architectures_resource() -> str:
    """Return all supported CPU architecture reference information."""
    return list_supported_architectures()


# ──────────────────────────────────────────────
# Prompt: Binary Analysis Assistant
# ──────────────────────────────────────────────
@mcp.prompt()
def binary_analysis_prompt(file_path: str) -> str:
    """Generate a guided prompt for analyzing a binary file."""
    return (
        f"Please help me analyze the binary file: {file_path}\n\n"
        "Recommended analysis steps:\n"
        "1. Use get_binary_info to get basic file info (format, arch, sections, etc.)\n"
        "2. Use disassemble_entrypoint to view entrypoint code\n"
        "3. Use disassemble_file_section to disassemble the .text section\n"
        "4. Use search_instructions_in_file to find key instruction patterns (e.g. call, syscall)\n"
        "5. Use analyze_code_flow for control flow analysis\n"
        "6. Use check_security to check binary security features\n"
        "7. Dive deeper into specific addresses based on findings\n"
    )


def main():
    """Entry point for the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
