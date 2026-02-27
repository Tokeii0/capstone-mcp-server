"""Security analysis: checksec, PLT/GOT analysis, hex dump."""

import os
from typing import Optional

import lief

from .disassembler import ArchType


# ═══════════════════════════════════════════════
# 1. Checksec - Security Feature Detection
# ═══════════════════════════════════════════════

def checksec(file_path: str) -> dict:
    """Detect security features of a binary (similar to checksec tool).

    Checks: NX, PIE, RELRO, Stack Canary, FORTIFY, RPATH, RUNPATH, Stripped.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    binary = lief.parse(file_path)
    if binary is None:
        raise ValueError(f"Unable to parse binary: {file_path}")

    result = {
        "file": os.path.basename(file_path),
        "format": "Unknown",
    }

    if isinstance(binary, lief.ELF.Binary):
        result["format"] = "ELF"
        result.update(_checksec_elf(binary))
    elif isinstance(binary, lief.PE.Binary):
        result["format"] = "PE"
        result.update(_checksec_pe(binary))
    elif isinstance(binary, lief.MachO.Binary):
        result["format"] = "Mach-O"
        result.update(_checksec_macho(binary))

    return result


def _checksec_elf(binary: lief.ELF.Binary) -> dict:
    """Check security features for ELF binaries."""
    result = {}

    # NX (No-eXecute / DEP)
    has_gnu_stack = False
    nx_enabled = False
    for seg in binary.segments:
        if seg.type == lief.ELF.Segment.TYPE.GNU_STACK:
            has_gnu_stack = True
            # If RWE flags don't include EXECUTE, NX is enabled
            nx_enabled = not bool(seg.flags & lief.ELF.Segment.FLAGS.X)
            break
    result["NX"] = "Enabled" if nx_enabled else ("Disabled" if has_gnu_stack else "Unknown (no GNU_STACK)")

    # PIE (Position Independent Executable)
    if binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYN:
        result["PIE"] = "Enabled (PIE)"
    elif binary.header.file_type == lief.ELF.Header.FILE_TYPE.EXEC:
        result["PIE"] = "Disabled"
    else:
        result["PIE"] = f"Unknown ({binary.header.file_type})"

    # RELRO
    has_relro = False
    full_relro = False
    for seg in binary.segments:
        if seg.type == lief.ELF.Segment.TYPE.GNU_RELRO:
            has_relro = True
            break
    if has_relro:
        # Check for BIND_NOW flag indicating Full RELRO
        has_bind_now = False
        if binary.has(lief.ELF.DynamicEntry.TAG.FLAGS):
            flags_entry = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS)
            if flags_entry and (flags_entry.value & 0x8):  # DF_BIND_NOW = 0x8
                has_bind_now = True
        if binary.has(lief.ELF.DynamicEntry.TAG.BIND_NOW):
            has_bind_now = True
        if binary.has(lief.ELF.DynamicEntry.TAG.FLAGS_1):
            flags1_entry = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS_1)
            if flags1_entry and (flags1_entry.value & 0x1):  # DF_1_NOW = 0x1
                has_bind_now = True

        if has_bind_now:
            result["RELRO"] = "Full RELRO"
            full_relro = True
        else:
            result["RELRO"] = "Partial RELRO"
    else:
        result["RELRO"] = "No RELRO"

    # Stack Canary
    canary_syms = {"__stack_chk_fail", "__stack_chk_guard", "__stack_smash_handler"}
    imported = {s.name for s in binary.imported_symbols if s.name}
    has_canary = bool(canary_syms & imported)
    result["Stack Canary"] = "Found" if has_canary else "Not found"

    # FORTIFY
    fortify_funcs = {s.name for s in binary.imported_symbols if s.name and s.name.endswith("_chk")}
    result["FORTIFY"] = f"Found ({len(fortify_funcs)} functions)" if fortify_funcs else "Not found"

    # RPATH / RUNPATH
    rpath = ""
    runpath = ""
    if binary.has(lief.ELF.DynamicEntry.TAG.RPATH):
        entry = binary.get(lief.ELF.DynamicEntry.TAG.RPATH)
        rpath = entry.name if hasattr(entry, "name") else str(entry.value)
    if binary.has(lief.ELF.DynamicEntry.TAG.RUNPATH):
        entry = binary.get(lief.ELF.DynamicEntry.TAG.RUNPATH)
        runpath = entry.name if hasattr(entry, "name") else str(entry.value)
    result["RPATH"] = rpath if rpath else "None"
    result["RUNPATH"] = runpath if runpath else "None"

    # Stripped
    result["Stripped"] = "Yes" if not binary.has_section(".symtab") else "No"

    return result


def _checksec_pe(binary: lief.PE.Binary) -> dict:
    """Check security features for PE binaries."""
    result = {}

    # DEP / NX
    if binary.has_configuration:
        opt_header = binary.optional_header
        result["DEP/NX"] = "Enabled" if opt_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NX_COMPAT) else "Disabled"
        result["ASLR"] = "Enabled" if opt_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE) else "Disabled"
        result["High Entropy ASLR"] = "Enabled" if opt_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.HIGH_ENTROPY_VA) else "Disabled"
        result["SEH"] = "Disabled" if opt_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NO_SEH) else "Enabled"
        result["SafeSEH"] = "Present" if binary.has_configuration and hasattr(binary, "load_configuration") else "Unknown"
        result["CFG"] = "Enabled" if opt_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.GUARD_CF) else "Disabled"
        result["Authenticode"] = "Signed" if binary.has_signatures else "Not signed"
    else:
        result["DEP/NX"] = "Unknown"
        result["ASLR"] = "Unknown"

    return result


def _checksec_macho(binary: lief.MachO.Binary) -> dict:
    """Check security features for Mach-O binaries."""
    result = {}
    result["PIE"] = "Enabled" if binary.is_pie else "Disabled"
    result["NX Heap"] = "Enabled" if binary.has(lief.MachO.LoadCommand.TYPE.VERSION_MIN_MACOSX) else "Unknown"

    # Check for stack canary
    imports = {s.name for s in binary.imported_symbols if s.name}
    result["Stack Canary"] = "Found" if "___stack_chk_fail" in imports or "__stack_chk_fail" in imports else "Not found"

    # ARC (Automatic Reference Counting)
    result["ARC"] = "Enabled" if "_objc_release" in imports else "Not detected"

    # Code Signing
    result["Code Signed"] = "Yes" if binary.has_code_signature else "No"

    return result


# ═══════════════════════════════════════════════
# 2. PLT / GOT Analysis (ELF)
# ═══════════════════════════════════════════════

def analyze_plt_got(file_path: str) -> dict:
    """Analyze PLT (Procedure Linkage Table) and GOT (Global Offset Table) entries.

    Essential for understanding dynamic linking and ELF exploitation.
    """
    binary = lief.parse(file_path)
    if binary is None:
        raise ValueError(f"Unable to parse binary: {file_path}")

    if not isinstance(binary, lief.ELF.Binary):
        return {"error": "PLT/GOT analysis is only supported for ELF binaries.",
                "format": type(binary).__name__}

    result = {
        "file": os.path.basename(file_path),
        "relocations": [],
        "plt_entries": [],
        "got_address": None,
        "got_plt_address": None,
    }

    # Find GOT sections
    for section in binary.sections:
        name = section.name.strip("\x00")
        if name == ".got":
            result["got_address"] = f"0x{section.virtual_address:x}"
        elif name == ".got.plt":
            result["got_plt_address"] = f"0x{section.virtual_address:x}"

    # PLT relocations
    for reloc in binary.pltgot_relocations:
        entry = {
            "address": f"0x{reloc.address:x}",
            "type": str(reloc.type).split(".")[-1] if hasattr(reloc, "type") else "unknown",
        }
        if reloc.has_symbol:
            entry["symbol"] = reloc.symbol.name
            if reloc.symbol.has_version:
                entry["version"] = str(reloc.symbol.symbol_version)
        result["relocations"].append(entry)

    # Dynamic relocations
    dynamic_relocs = []
    for reloc in binary.dynamic_relocations:
        entry = {
            "address": f"0x{reloc.address:x}",
            "type": str(reloc.type).split(".")[-1] if hasattr(reloc, "type") else "unknown",
        }
        if reloc.has_symbol:
            entry["symbol"] = reloc.symbol.name
        dynamic_relocs.append(entry)
    result["dynamic_relocations"] = dynamic_relocs

    return result


# ═══════════════════════════════════════════════
# 3. IAT Analysis (PE)
# ═══════════════════════════════════════════════

def analyze_iat(file_path: str) -> dict:
    """Analyze Import Address Table for PE binaries.

    Shows DLL imports with their IAT addresses - useful for hooking and patching.
    """
    binary = lief.parse(file_path)
    if binary is None:
        raise ValueError(f"Unable to parse binary: {file_path}")

    if not isinstance(binary, lief.PE.Binary):
        return {"error": "IAT analysis is only supported for PE binaries."}

    result = {
        "file": os.path.basename(file_path),
        "imports": {},
        "total_dlls": 0,
        "total_functions": 0,
    }

    for imp in binary.imports:
        dll_name = imp.name
        entries = []
        for entry in imp.entries:
            e = {
                "name": entry.name if entry.name else f"Ordinal_{entry.data & 0xFFFF}",
                "iat_address": f"0x{entry.iat_address:x}" if entry.iat_address else "N/A",
                "hint": entry.hint,
            }
            entries.append(e)
        result["imports"][dll_name] = entries
        result["total_functions"] += len(entries)

    result["total_dlls"] = len(result["imports"])
    return result


# ═══════════════════════════════════════════════
# 4. Hex Dump
# ═══════════════════════════════════════════════

def hex_dump(data: bytes, base_address: int = 0, length: Optional[int] = None) -> str:
    """Generate a formatted hex dump of binary data.

    Format: ADDRESS  HH HH HH HH HH HH HH HH  HH HH HH HH HH HH HH HH  |ASCII...........|
    """
    if length:
        data = data[:length]

    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        addr = base_address + offset

        # Hex part
        hex_parts = []
        for i in range(16):
            if i < len(chunk):
                hex_parts.append(f"{chunk[i]:02x}")
            else:
                hex_parts.append("  ")
        hex_left = " ".join(hex_parts[:8])
        hex_right = " ".join(hex_parts[8:])

        # ASCII part
        ascii_part = ""
        for b in chunk:
            if 32 <= b < 127:
                ascii_part += chr(b)
            else:
                ascii_part += "."

        lines.append(f"0x{addr:08x}  {hex_left}  {hex_right}  |{ascii_part}|")

    return "\n".join(lines)
