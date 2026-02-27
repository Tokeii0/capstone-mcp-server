# Capstone MCP Server

**中文** | [English](./README_EN.md)

基于 [Capstone](https://www.capstone-engine.org/) 反汇编引擎的 MCP (Model Context Protocol) 服务器，为大语言模型提供二进制分析能力。

## 功能特性

- **多架构支持**: x86 (16/32/64)、ARM/ARM64、MIPS (32/64)、PowerPC (32/64)
- **多格式解析**: PE、ELF、Mach-O 二进制文件自动识别与解析
- **反汇编工具**: 支持 hex 字节串、文件区段、虚拟地址、文件偏移等多种输入方式
- **控制流分析**: 基本块识别、跳转/调用/返回分析
- **指令搜索**: 按助记符或指令类别过滤搜索
- **架构自动检测**: 从 PE/ELF/Mach-O 文件头自动推断 CPU 架构
- **ROP Gadget 搜索**: 查找以 ret 结尾的指令片段，用于 ROP 链构造
- **安全特性检测**: 类似 checksec，检测 NX/PIE/RELRO/Canary/ASLR 等
- **PLT/GOT & IAT 分析**: ELF 动态链接表与 PE 导入表分析
- **字符串提取**: 支持 ASCII 和 UTF-16LE 编码的可读字符串扫描
- **XOR 编解码**: 单字节暴力破解与多字节密钥 XOR 运算
- **缓冲区溢出辅助**: De Bruijn 序列生成与偏移计算（pattern_create/offset）
- **加密常量识别**: 检测 AES S-Box、SHA、MD5、TEA、CRC32、Base64 等常量
- **Shellcode 分析**: NOP sled、syscall、jmp/call esp 等模式检测
- **Syscall 查找**: Linux x86/x64/ARM/ARM64 系统调用表查询
- **Hex Dump**: 格式化的十六进制转储查看

## 提供的 MCP 工具

### 基础反汇编工具

| 工具 | 说明 |
|------|------|
| `list_supported_architectures` | 列出所有支持的 CPU 架构 |
| `disassemble_hex` | 反汇编十六进制字节串 |
| `disassemble_file_section` | 反汇编二进制文件的指定区段 |
| `disassemble_at_address` | 反汇编文件中指定虚拟地址处的代码 |
| `disassemble_entrypoint` | 反汇编二进制文件入口点 |
| `disassemble_raw_offset` | 反汇编文件偏移处的原始字节 |
| `get_binary_info` | 获取二进制文件元信息（格式、架构、区段、导入/导出） |
| `search_instructions` | 在 hex 字节串中搜索指令模式 |
| `search_instructions_in_file` | 在二进制文件中搜索指令模式 |
| `analyze_code_flow` | 对机器码进行控制流分析 |

### CTF / 逆向扩展工具

| 工具 | 说明 | CTF 场景 |
|------|------|----------|
| `find_rop_gadgets_hex` | 在 hex 字节串中搜索 ROP gadgets | Pwn - ROP 链构造 |
| `find_rop_gadgets_in_file` | 在二进制文件中搜索 ROP gadgets | Pwn - ROP 链构造 |
| `extract_strings_from_file` | 提取可读字符串（类似 `strings`） | RE / Misc / Forensics |
| `xor_brute_force` | 单字节 XOR 暴力破解 | Crypto / RE |
| `xor_encode_decode` | 指定密钥 XOR 编解码 | Crypto / RE |
| `buffer_overflow_pattern` | 生成/查找缓冲区溢出 pattern（De Bruijn） | Pwn - 偏移计算 |
| `check_security` | 检测安全特性（类似 `checksec`） | Pwn - 漏洞利用前置 |
| `analyze_plt_got_table` | 分析 ELF PLT/GOT 或 PE IAT 表 | Pwn - GOT overwrite |
| `hex_dump_file` | 十六进制转储查看文件内容 | RE / Forensics |
| `detect_crypto_in_file` | 检测加密算法常量（AES/SHA/MD5/TEA 等） | Crypto / RE |
| `analyze_shellcode_hex` | Shellcode 综合分析（模式检测+统计） | Pwn / RE |
| `syscall_lookup` | Linux 系统调用查找（按编号或名称） | Pwn / RE |
| `syscall_list` | 列出平台全部系统调用表 | Pwn / RE |

## 安装

```bash
# 克隆项目
git clone <repo-url>
cd capstone-mcp-server

# 安装依赖
pip install -e .
```

## 运行

### 直接运行

```bash
capstone-mcp
```

### 通过 Python 模块运行

```bash
python -m capstone_mcp.server
```

### 使用 MCP Inspector 调试

```bash
mcp dev src/capstone_mcp/server.py
```

## 配置 MCP 客户端

### Windsurf / Claude Desktop

在 MCP 配置文件中添加:

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

或者使用 `uv` 运行:

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

## 使用示例

### 反汇编 hex 字节串

大模型可调用 `disassemble_hex` 工具:

```
输入: hex_code="554889e54883ec10c745fc00000000b8000000004883c4105dc3", arch="x86_64"
```

输出:
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

### 分析二进制文件

```
1. 调用 get_binary_info("C:/path/to/program.exe")  → 获取文件概要
2. 调用 disassemble_entrypoint("C:/path/to/program.exe")  → 查看入口点
3. 调用 search_instructions_in_file("C:/path/to/program.exe", group="call")  → 查找所有调用
```

## 依赖

- **Python** >= 3.10
- **[mcp](https://pypi.org/project/mcp/)** - Model Context Protocol SDK
- **[capstone](https://pypi.org/project/capstone/)** - 反汇编引擎
- **[LIEF](https://pypi.org/project/lief/)** - 二进制文件解析库

## 许可证

MIT
