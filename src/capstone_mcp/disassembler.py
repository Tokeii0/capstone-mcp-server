"""Core Capstone disassembly engine."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import capstone
from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_MIPS,
    CS_ARCH_PPC,
    CS_ARCH_X86,
    CS_MODE_16,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_BIG_ENDIAN,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MIPS32,
    CS_MODE_MIPS64,
    CS_MODE_THUMB,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_GRP_INT,
    CS_GRP_IRET,
    CS_OPT_ON,
    Cs,
    CsInsn,
)


class ArchType(str, Enum):
    X86_16 = "x86_16"
    X86_32 = "x86_32"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM_THUMB = "arm_thumb"
    ARM64 = "arm64"
    MIPS32 = "mips32"
    MIPS64 = "mips64"
    MIPS32_BE = "mips32_be"
    MIPS64_BE = "mips64_be"
    PPC32 = "ppc32"
    PPC64 = "ppc64"


ARCH_MAP: dict[ArchType, tuple[int, int]] = {
    ArchType.X86_16: (CS_ARCH_X86, CS_MODE_16),
    ArchType.X86_32: (CS_ARCH_X86, CS_MODE_32),
    ArchType.X86_64: (CS_ARCH_X86, CS_MODE_64),
    ArchType.ARM: (CS_ARCH_ARM, CS_MODE_ARM),
    ArchType.ARM_THUMB: (CS_ARCH_ARM, CS_MODE_THUMB),
    ArchType.ARM64: (CS_ARCH_ARM64, CS_MODE_ARM),
    ArchType.MIPS32: (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN),
    ArchType.MIPS64: (CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN),
    ArchType.MIPS32_BE: (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
    ArchType.MIPS64_BE: (CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN),
    ArchType.PPC32: (CS_ARCH_PPC, CS_MODE_32 + CS_MODE_BIG_ENDIAN),
    ArchType.PPC64: (CS_ARCH_PPC, CS_MODE_64 + CS_MODE_BIG_ENDIAN),
}


@dataclass
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    size: int
    groups: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "address": f"0x{self.address:x}",
            "mnemonic": self.mnemonic,
            "operands": self.op_str,
            "bytes": self.bytes_hex,
            "size": self.size,
            "groups": self.groups,
        }

    def to_asm_line(self) -> str:
        return f"0x{self.address:08x}:  {self.bytes_hex:<24s}  {self.mnemonic:<8s} {self.op_str}"


def _classify_groups(insn: CsInsn) -> list[str]:
    """Classify instruction into semantic groups."""
    groups = []
    if insn.group(CS_GRP_CALL):
        groups.append("call")
    if insn.group(CS_GRP_JUMP):
        groups.append("jump")
    if insn.group(CS_GRP_RET):
        groups.append("ret")
    if insn.group(CS_GRP_INT):
        groups.append("interrupt")
    if insn.group(CS_GRP_IRET):
        groups.append("iret")
    return groups


def create_engine(arch: ArchType) -> Cs:
    """Create a Capstone disassembly engine for the given architecture."""
    if arch not in ARCH_MAP:
        raise ValueError(f"Unsupported architecture: {arch}. Supported: {list(ARCH_MAP.keys())}")
    cs_arch, cs_mode = ARCH_MAP[arch]
    md = Cs(cs_arch, cs_mode)
    md.detail = True
    md.skipdata = True
    return md


def disassemble(
    code: bytes,
    arch: ArchType,
    base_address: int = 0,
    count: int = 0,
) -> list[Instruction]:
    """Disassemble raw bytes into a list of Instructions."""
    md = create_engine(arch)
    instructions: list[Instruction] = []
    for insn in md.disasm(code, base_address, count=count):
        inst = Instruction(
            address=insn.address,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            bytes_hex=insn.bytes.hex(),
            size=insn.size,
            groups=_classify_groups(insn),
        )
        instructions.append(inst)
    return instructions


def disassemble_to_text(
    code: bytes,
    arch: ArchType,
    base_address: int = 0,
    count: int = 0,
) -> str:
    """Disassemble raw bytes and return formatted assembly text."""
    instructions = disassemble(code, arch, base_address, count)
    if not instructions:
        return "(no valid instructions decoded)"
    lines = [inst.to_asm_line() for inst in instructions]
    return "\n".join(lines)


def get_supported_architectures() -> list[dict[str, str]]:
    """Return list of supported architectures with descriptions."""
    descriptions = {
        ArchType.X86_16: "Intel x86 16-bit (Real Mode)",
        ArchType.X86_32: "Intel x86 32-bit (IA-32)",
        ArchType.X86_64: "Intel x86 64-bit (AMD64 / x86-64)",
        ArchType.ARM: "ARM 32-bit (ARM mode)",
        ArchType.ARM_THUMB: "ARM 32-bit (Thumb mode)",
        ArchType.ARM64: "ARM 64-bit (AArch64)",
        ArchType.MIPS32: "MIPS 32-bit (Little Endian)",
        ArchType.MIPS64: "MIPS 64-bit (Little Endian)",
        ArchType.MIPS32_BE: "MIPS 32-bit (Big Endian)",
        ArchType.MIPS64_BE: "MIPS 64-bit (Big Endian)",
        ArchType.PPC32: "PowerPC 32-bit (Big Endian)",
        ArchType.PPC64: "PowerPC 64-bit (Big Endian)",
    }
    return [{"arch": a.value, "description": descriptions[a]} for a in ArchType]


def search_pattern(
    code: bytes,
    arch: ArchType,
    base_address: int,
    mnemonic_pattern: Optional[str] = None,
    group_filter: Optional[str] = None,
) -> list[Instruction]:
    """Search for instructions matching a mnemonic pattern or group."""
    instructions = disassemble(code, arch, base_address)
    results = []
    for inst in instructions:
        if mnemonic_pattern and mnemonic_pattern.lower() not in inst.mnemonic.lower():
            continue
        if group_filter and group_filter.lower() not in [g.lower() for g in inst.groups]:
            continue
        if not mnemonic_pattern and not group_filter:
            continue
        results.append(inst)
    return results


def analyze_control_flow(
    code: bytes,
    arch: ArchType,
    base_address: int = 0,
) -> dict:
    """Analyze control flow of disassembled code, identifying basic blocks and branches."""
    instructions = disassemble(code, arch, base_address)
    if not instructions:
        return {"blocks": [], "edges": [], "summary": "No instructions decoded."}

    blocks: list[dict] = []
    edges: list[dict] = []
    current_block_start = instructions[0].address
    current_block_insns: list[str] = []

    calls = []
    jumps = []
    rets = []

    for inst in instructions:
        current_block_insns.append(inst.to_asm_line())

        if "call" in inst.groups:
            calls.append({"from": f"0x{inst.address:x}", "target": inst.op_str})
        if "jump" in inst.groups:
            jumps.append({"from": f"0x{inst.address:x}", "target": inst.op_str})
        if "ret" in inst.groups:
            rets.append(f"0x{inst.address:x}")

        is_block_end = any(g in inst.groups for g in ("jump", "ret", "iret"))
        if is_block_end:
            blocks.append({
                "start": f"0x{current_block_start:x}",
                "end": f"0x{inst.address:x}",
                "instruction_count": len(current_block_insns),
                "instructions": current_block_insns,
            })
            if "jump" in inst.groups:
                edges.append({
                    "from_block": f"0x{current_block_start:x}",
                    "to": inst.op_str,
                    "type": "jump",
                })
            current_block_insns = []
            current_block_start = inst.address + inst.size

    if current_block_insns:
        blocks.append({
            "start": f"0x{current_block_start:x}",
            "end": f"0x{instructions[-1].address:x}",
            "instruction_count": len(current_block_insns),
            "instructions": current_block_insns,
        })

    summary = (
        f"Total instructions: {len(instructions)}, "
        f"Basic blocks: {len(blocks)}, "
        f"Calls: {len(calls)}, Jumps: {len(jumps)}, Returns: {len(rets)}"
    )

    return {
        "total_instructions": len(instructions),
        "basic_blocks": blocks,
        "edges": edges,
        "calls": calls,
        "jumps": jumps,
        "returns": rets,
        "summary": summary,
    }
