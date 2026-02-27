"""Binary file parser using LIEF for PE/ELF/Mach-O formats."""

import os
from dataclasses import dataclass, field
from typing import Optional

import lief

from .disassembler import ArchType


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "virtual_address": f"0x{self.virtual_address:x}",
            "virtual_size": self.virtual_size,
            "raw_size": self.raw_size,
            "entropy": round(self.entropy, 4),
            "characteristics": self.characteristics,
        }


@dataclass
class BinaryInfo:
    format: str
    arch: str
    bits: int
    entrypoint: int
    is_pie: bool
    sections: list[SectionInfo]
    imports: list[str]
    exports: list[str]
    detected_arch: Optional[ArchType] = None

    def to_dict(self) -> dict:
        return {
            "format": self.format,
            "architecture": self.arch,
            "bits": self.bits,
            "entrypoint": f"0x{self.entrypoint:x}",
            "is_pie": self.is_pie,
            "detected_capstone_arch": self.detected_arch.value if self.detected_arch else None,
            "sections": [s.to_dict() for s in self.sections],
            "imports_count": len(self.imports),
            "imports": self.imports[:100],  # limit for readability
            "exports_count": len(self.exports),
            "exports": self.exports[:100],
        }


def _detect_arch(binary: lief.Binary) -> Optional[ArchType]:
    """Auto-detect Capstone architecture from binary metadata."""
    header = binary.header
    if isinstance(binary, lief.PE.Binary):
        machine = binary.header.machine
        if machine == lief.PE.Header.MACHINE_TYPES.AMD64:
            return ArchType.X86_64
        elif machine == lief.PE.Header.MACHINE_TYPES.I386:
            return ArchType.X86_32
        elif machine == lief.PE.Header.MACHINE_TYPES.ARM:
            return ArchType.ARM
        elif machine == lief.PE.Header.MACHINE_TYPES.ARM64:
            return ArchType.ARM64
    elif isinstance(binary, lief.ELF.Binary):
        machine = binary.header.machine_type
        if machine == lief.ELF.ARCH.x86_64:
            return ArchType.X86_64
        elif machine == lief.ELF.ARCH.i386:
            return ArchType.X86_32
        elif machine == lief.ELF.ARCH.ARM:
            return ArchType.ARM
        elif machine == lief.ELF.ARCH.AARCH64:
            return ArchType.ARM64
        elif machine == lief.ELF.ARCH.MIPS:
            elf_class = binary.header.identity_class
            if elf_class == lief.ELF.ELF_CLASS.CLASS64:
                return ArchType.MIPS64
            return ArchType.MIPS32
        elif machine == lief.ELF.ARCH.PPC:
            return ArchType.PPC32
        elif machine == lief.ELF.ARCH.PPC64:
            return ArchType.PPC64
    elif isinstance(binary, lief.MachO.Binary):
        cpu = binary.header.cpu_type
        if cpu == lief.MachO.Header.CPU_TYPE_LIST.x86_64:
            return ArchType.X86_64
        elif cpu == lief.MachO.Header.CPU_TYPE_LIST.x86:
            return ArchType.X86_32
        elif cpu == lief.MachO.Header.CPU_TYPE_LIST.ARM:
            return ArchType.ARM
        elif cpu == lief.MachO.Header.CPU_TYPE_LIST.ARM64:
            return ArchType.ARM64
    return None


def _get_section_chars(section, binary) -> list[str]:
    """Get human-readable section characteristics."""
    chars = []
    if isinstance(binary, lief.PE.Binary):
        s_chars = section.characteristics_lists
        for c in s_chars:
            chars.append(str(c).split(".")[-1])
    elif isinstance(binary, lief.ELF.Binary):
        flags = section.flags_list
        for f in flags:
            chars.append(str(f).split(".")[-1])
    return chars


def parse_binary(file_path: str) -> BinaryInfo:
    """Parse a binary file and extract metadata."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    binary = lief.parse(file_path)
    if binary is None:
        raise ValueError(f"Unable to parse binary: {file_path}. Unsupported or corrupted format.")

    # Determine format
    if isinstance(binary, lief.PE.Binary):
        fmt = "PE"
    elif isinstance(binary, lief.ELF.Binary):
        fmt = "ELF"
    elif isinstance(binary, lief.MachO.Binary):
        fmt = "Mach-O"
    else:
        fmt = "Unknown"

    detected_arch = _detect_arch(binary)

    # Architecture string
    arch_str = str(binary.header.machine_type) if hasattr(binary.header, "machine_type") else "unknown"
    if isinstance(binary, lief.PE.Binary):
        arch_str = str(binary.header.machine)

    # Bits
    bits = 64 if detected_arch and "64" in detected_arch.value else 32

    # Entrypoint
    entrypoint = binary.entrypoint if hasattr(binary, "entrypoint") else 0

    # PIE
    is_pie = binary.is_pie if hasattr(binary, "is_pie") else False

    # Sections
    sections = []
    for section in binary.sections:
        si = SectionInfo(
            name=section.name,
            virtual_address=section.virtual_address,
            virtual_size=section.size,
            raw_size=len(section.content) if hasattr(section, "content") else 0,
            entropy=section.entropy,
            characteristics=_get_section_chars(section, binary),
        )
        sections.append(si)

    # Imports
    imports = []
    if isinstance(binary, lief.PE.Binary):
        for imp in binary.imports:
            for entry in imp.entries:
                if entry.name:
                    imports.append(f"{imp.name}!{entry.name}")
    elif isinstance(binary, lief.ELF.Binary):
        for sym in binary.imported_symbols:
            if sym.name:
                imports.append(sym.name)
    elif isinstance(binary, lief.MachO.Binary):
        for sym in binary.imported_symbols:
            if sym.name:
                imports.append(sym.name)

    # Exports
    exports = []
    if isinstance(binary, lief.PE.Binary):
        if binary.has_exports:
            for entry in binary.get_export().entries:
                if entry.name:
                    exports.append(entry.name)
    elif isinstance(binary, lief.ELF.Binary):
        for sym in binary.exported_symbols:
            if sym.name:
                exports.append(sym.name)
    elif isinstance(binary, lief.MachO.Binary):
        for sym in binary.exported_symbols:
            if sym.name:
                exports.append(sym.name)

    return BinaryInfo(
        format=fmt,
        arch=arch_str,
        bits=bits,
        entrypoint=entrypoint,
        is_pie=is_pie,
        sections=sections,
        imports=imports,
        exports=exports,
        detected_arch=detected_arch,
    )


def read_section_bytes(file_path: str, section_name: str) -> tuple[bytes, int]:
    """Read raw bytes from a named section. Returns (bytes, virtual_address)."""
    binary = lief.parse(file_path)
    if binary is None:
        raise ValueError(f"Unable to parse binary: {file_path}")

    for section in binary.sections:
        if section.name.strip("\x00") == section_name.strip("\x00"):
            content = bytes(section.content)
            return content, section.virtual_address

    available = [s.name for s in binary.sections]
    raise ValueError(
        f"Section '{section_name}' not found. Available sections: {available}"
    )


def read_bytes_at_offset(file_path: str, offset: int, size: int) -> bytes:
    """Read raw bytes from a file at a given offset."""
    with open(file_path, "rb") as f:
        f.seek(offset)
        return f.read(size)


def read_bytes_at_va(file_path: str, virtual_address: int, size: int) -> tuple[bytes, int]:
    """Read bytes at a virtual address from a binary. Returns (bytes, va)."""
    binary = lief.parse(file_path)
    if binary is None:
        raise ValueError(f"Unable to parse binary: {file_path}")

    # Convert VA to file offset (compatible with multiple LIEF versions)
    offset = _va_to_file_offset(binary, virtual_address)
    with open(file_path, "rb") as f:
        f.seek(offset)
        data = f.read(size)
    return data, virtual_address


def _va_to_file_offset(binary: lief.Binary, virtual_address: int) -> int:
    """Convert a virtual address to a file offset, with LIEF version compatibility."""
    # LIEF >= 0.14: va_to_offset
    if hasattr(binary, "va_to_offset"):
        return binary.va_to_offset(virtual_address)
    # Older LIEF: virtual_address_to_offset
    if hasattr(binary, "virtual_address_to_offset"):
        return binary.virtual_address_to_offset(virtual_address)
    # Manual fallback: iterate sections to find the mapping
    imagebase = 0
    if isinstance(binary, lief.PE.Binary):
        imagebase = binary.optional_header.imagebase
    rva = virtual_address - imagebase
    for section in binary.sections:
        sec_va = section.virtual_address
        sec_size = section.size
        if sec_va <= rva < sec_va + sec_size:
            # PE section raw data offset
            if isinstance(binary, lief.PE.Binary):
                return section.offset + (rva - sec_va)
            else:
                return section.file_offset + (rva - sec_va)
    raise ValueError(f"Cannot map VA 0x{virtual_address:x} to file offset")
