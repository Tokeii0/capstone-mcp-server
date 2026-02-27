# Capstone MCP Server

[中文](./README.md) | **English**

An MCP (Model Context Protocol) server based on the [Capstone](https://www.capstone-engine.org/) disassembly engine, providing binary analysis capabilities for large language models.

## Features

- **Multi-architecture support**: x86 (16/32/64), ARM/ARM64, MIPS (32/64), PowerPC (32/64)
- **Multi-format parsing**: Automatic recognition and parsing of PE, ELF, and Mach-O binaries
- **Disassembly tools**: Multiple input methods including hex strings, file sections, virtual addresses, and file offsets
- **Control flow analysis**: Basic block identification, jump/call/return analysis
- **Instruction search**: Filter and search by mnemonic or instruction group
- **Architecture auto-detection**: Infer CPU architecture from PE/ELF/Mach-O headers
- **ROP Gadget search**: Find instruction sequences ending with `ret` for ROP chain construction
- **Security feature detection**: checksec-like detection of NX/PIE/RELRO/Canary/ASLR, etc.
- **PLT/GOT & IAT analysis**: ELF dynamic linking table and PE import table analysis
- **String extraction**: Scan for readable strings in ASCII and UTF-16LE encodings
- **XOR encode/decode**: Single-byte brute force and multi-byte key XOR operations
- **Buffer overflow helpers**: De Bruijn sequence generation and offset calculation (pattern_create/offset)
- **Crypto constant detection**: Detect AES S-Box, SHA, MD5, TEA, CRC32, Base64, and other constants
- **Shellcode analysis**: NOP sled, syscall, jmp/call esp pattern detection
- **Syscall lookup**: Linux x86/x64/ARM/ARM64 syscall table queries
- **Hex Dump**: Formatted hexadecimal dump viewer
- **Cross-reference search**: Find all references to a target address in code (call/jump/immediate/memory access)

## MCP Tools

### Basic Disassembly Tools

| Tool | Description |
|------|-------------|
| `list_supported_architectures` | List all supported CPU architectures |
| `disassemble_hex` | Disassemble a hex byte string |
| `disassemble_file_section` | Disassemble a specific section of a binary file |
| `disassemble_at_address` | Disassemble code at a virtual address in a file |
| `disassemble_entrypoint` | Disassemble the entry point of a binary |
| `disassemble_raw_offset` | Disassemble raw bytes at a file offset |
| `get_binary_info` | Get binary file metadata (format, arch, sections, imports/exports) |
| `search_instructions` | Search instruction patterns in a hex byte string |
| `search_instructions_in_file` | Search instruction patterns in a binary file |
| `analyze_code_flow` | Perform control flow analysis on machine code |
| `find_xrefs_hex` | Find cross-references to a target address in hex byte string |
| `find_xrefs_in_file` | Find cross-references to a target address in a binary file |

### CTF / Reverse Engineering Tools

| Tool | Description | CTF Use Case |
|------|-------------|--------------|
| `find_rop_gadgets_hex` | Search ROP gadgets in hex byte string | Pwn - ROP chain |
| `find_rop_gadgets_in_file` | Search ROP gadgets in binary file | Pwn - ROP chain |
| `extract_strings_from_file` | Extract readable strings (like `strings`) | RE / Misc / Forensics |
| `xor_brute_force` | Single-byte XOR brute force | Crypto / RE |
| `xor_encode_decode` | XOR encode/decode with a given key | Crypto / RE |
| `buffer_overflow_pattern` | Generate/find buffer overflow pattern (De Bruijn) | Pwn - Offset calc |
| `check_security` | Detect security features (like `checksec`) | Pwn - Pre-exploit |
| `analyze_plt_got_table` | Analyze ELF PLT/GOT or PE IAT tables | Pwn - GOT overwrite |
| `hex_dump_file` | Hex dump file contents | RE / Forensics |
| `detect_crypto_in_file` | Detect crypto algorithm constants (AES/SHA/MD5/TEA, etc.) | Crypto / RE |
| `analyze_shellcode_hex` | Comprehensive shellcode analysis (pattern detection + stats) | Pwn / RE |
| `syscall_lookup` | Linux syscall lookup (by number or name) | Pwn / RE |
| `syscall_list` | List all syscalls for a platform | Pwn / RE |

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd capstone-mcp-server

# Install dependencies
pip install -e .
```

## Running

### Direct execution

```bash
capstone-mcp
```

### Run as Python module

```bash
python -m capstone_mcp.server
```

### Debug with MCP Inspector

```bash
mcp dev src/capstone_mcp/server.py
```

## Configure MCP Client

### Windsurf / Claude Desktop

Add the following to your MCP configuration file:

```json
{
  "mcpServers": {
    "capstone-disasm": {
      "command": "python",
      "args": ["-m", "capstone_mcp.server"],
      "cwd": "/path/to/capstone-mcp-server"
    }
  }
}
```

Or run with `uv`:

```json
{
  "mcpServers": {
    "capstone-disasm": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/capstone-mcp-server", "capstone-mcp"]
    }
  }
}
```

## Usage Examples

### Disassemble hex byte string

An LLM can call the `disassemble_hex` tool:

```
Input: hex_code="554889e54883ec10c745fc00000000b8000000004883c4105dc3", arch="x86_64"
```

Output:
```
Architecture: x86_64
Base Address: 0x0
Input Size:   25 bytes
────────────────────────────────────────────────────────────────
0x00000000:  55                        push     rbp
0x00000001:  4889e5                    mov      rbp, rsp
0x00000004:  4883ec10                  sub      rsp, 0x10
0x00000008:  c745fc00000000            mov      dword ptr [rbp - 4], 0
0x0000000f:  b800000000                mov      eax, 0
0x00000014:  4883c410                  add      rsp, 0x10
0x00000018:  5d                        pop      rbp
0x00000019:  c3                        ret
```

### Analyze a binary file

```
1. Call get_binary_info("C:/path/to/program.exe")  → Get file overview
2. Call disassemble_entrypoint("C:/path/to/program.exe")  → View entry point
3. Call search_instructions_in_file("C:/path/to/program.exe", group="call")  → Find all calls
```

## Dependencies

- **Python** >= 3.10
- **[mcp](https://pypi.org/project/mcp/)** - Model Context Protocol SDK
- **[capstone](https://pypi.org/project/capstone/)** - Disassembly engine
- **[LIEF](https://pypi.org/project/lief/)** - Binary file parsing library

## License

MIT
