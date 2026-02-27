"""Linux syscall table lookup for x86 and x86_64."""

from typing import Optional

# ═══════════════════════════════════════════════
# Linux x86_64 syscall table (most common ones)
# ═══════════════════════════════════════════════

SYSCALL_X64: dict[int, dict] = {
    0: {"name": "read", "args": "fd, buf, count"},
    1: {"name": "write", "args": "fd, buf, count"},
    2: {"name": "open", "args": "filename, flags, mode"},
    3: {"name": "close", "args": "fd"},
    4: {"name": "stat", "args": "filename, statbuf"},
    5: {"name": "fstat", "args": "fd, statbuf"},
    6: {"name": "lstat", "args": "filename, statbuf"},
    7: {"name": "poll", "args": "ufds, nfds, timeout"},
    8: {"name": "lseek", "args": "fd, offset, whence"},
    9: {"name": "mmap", "args": "addr, len, prot, flags, fd, off"},
    10: {"name": "mprotect", "args": "start, len, prot"},
    11: {"name": "munmap", "args": "addr, len"},
    12: {"name": "brk", "args": "brk"},
    13: {"name": "rt_sigaction", "args": "sig, act, oact, sigsetsize"},
    14: {"name": "rt_sigprocmask", "args": "how, nset, oset, sigsetsize"},
    15: {"name": "rt_sigreturn", "args": ""},
    16: {"name": "ioctl", "args": "fd, cmd, arg"},
    17: {"name": "pread64", "args": "fd, buf, count, pos"},
    18: {"name": "pwrite64", "args": "fd, buf, count, pos"},
    19: {"name": "readv", "args": "fd, vec, vlen"},
    20: {"name": "writev", "args": "fd, vec, vlen"},
    21: {"name": "access", "args": "filename, mode"},
    22: {"name": "pipe", "args": "fildes"},
    23: {"name": "select", "args": "n, inp, outp, exp, tvp"},
    24: {"name": "sched_yield", "args": ""},
    25: {"name": "mremap", "args": "addr, old_len, new_len, flags, new_addr"},
    32: {"name": "dup", "args": "fildes"},
    33: {"name": "dup2", "args": "oldfd, newfd"},
    35: {"name": "nanosleep", "args": "rqtp, rmtp"},
    37: {"name": "alarm", "args": "seconds"},
    39: {"name": "getpid", "args": ""},
    41: {"name": "socket", "args": "family, type, protocol"},
    42: {"name": "connect", "args": "fd, uservaddr, addrlen"},
    43: {"name": "accept", "args": "fd, upeer_sockaddr, upeer_addrlen"},
    44: {"name": "sendto", "args": "fd, buff, len, flags, addr, addr_len"},
    45: {"name": "recvfrom", "args": "fd, ubuf, size, flags, addr, addr_len"},
    46: {"name": "sendmsg", "args": "fd, msg, flags"},
    47: {"name": "recvmsg", "args": "fd, msg, flags"},
    48: {"name": "shutdown", "args": "fd, how"},
    49: {"name": "bind", "args": "fd, umyaddr, addrlen"},
    50: {"name": "listen", "args": "fd, backlog"},
    53: {"name": "socketpair", "args": "family, type, protocol, usockvec"},
    56: {"name": "clone", "args": "clone_flags, newsp, parent_tidptr, child_tidptr, tls_val"},
    57: {"name": "fork", "args": ""},
    58: {"name": "vfork", "args": ""},
    59: {"name": "execve", "args": "filename, argv, envp"},
    60: {"name": "exit", "args": "error_code"},
    61: {"name": "wait4", "args": "upid, stat_addr, options, ru"},
    62: {"name": "kill", "args": "pid, sig"},
    63: {"name": "uname", "args": "name"},
    72: {"name": "fcntl", "args": "fd, cmd, arg"},
    78: {"name": "getdents", "args": "fd, dirent, count"},
    79: {"name": "getcwd", "args": "buf, size"},
    80: {"name": "chdir", "args": "filename"},
    82: {"name": "rename", "args": "oldname, newname"},
    83: {"name": "mkdir", "args": "pathname, mode"},
    84: {"name": "rmdir", "args": "pathname"},
    85: {"name": "creat", "args": "pathname, mode"},
    87: {"name": "unlink", "args": "pathname"},
    89: {"name": "readlink", "args": "path, buf, bufsiz"},
    90: {"name": "chmod", "args": "filename, mode"},
    91: {"name": "fchmod", "args": "fd, mode"},
    92: {"name": "chown", "args": "filename, user, group"},
    96: {"name": "gettimeofday", "args": "tv, tz"},
    97: {"name": "getrlimit", "args": "resource, rlim"},
    99: {"name": "sysinfo", "args": "info"},
    101: {"name": "ptrace", "args": "request, pid, addr, data"},
    102: {"name": "getuid", "args": ""},
    104: {"name": "getgid", "args": ""},
    105: {"name": "setuid", "args": "uid"},
    106: {"name": "setgid", "args": "gid"},
    107: {"name": "geteuid", "args": ""},
    108: {"name": "getegid", "args": ""},
    110: {"name": "getppid", "args": ""},
    157: {"name": "prctl", "args": "option, arg2, arg3, arg4, arg5"},
    186: {"name": "gettid", "args": ""},
    200: {"name": "tkill", "args": "pid, sig"},
    217: {"name": "getdents64", "args": "fd, dirent, count"},
    228: {"name": "clock_gettime", "args": "which_clock, tp"},
    231: {"name": "exit_group", "args": "error_code"},
    257: {"name": "openat", "args": "dfd, filename, flags, mode"},
    262: {"name": "newfstatat", "args": "dfd, filename, statbuf, flag"},
    288: {"name": "accept4", "args": "fd, upeer_sockaddr, upeer_addrlen, flags"},
    302: {"name": "prlimit64", "args": "pid, resource, new_rlim, old_rlim"},
    318: {"name": "getrandom", "args": "buf, count, flags"},
    322: {"name": "execveat", "args": "fd, filename, argv, envp, flags"},
    332: {"name": "statx", "args": "dfd, filename, flags, mask, buffer"},
    435: {"name": "clone3", "args": "uargs, size"},
}

# ═══════════════════════════════════════════════
# Linux x86 (32-bit) syscall table (most common)
# ═══════════════════════════════════════════════

SYSCALL_X86: dict[int, dict] = {
    1: {"name": "exit", "args": "error_code"},
    2: {"name": "fork", "args": ""},
    3: {"name": "read", "args": "fd, buf, count"},
    4: {"name": "write", "args": "fd, buf, count"},
    5: {"name": "open", "args": "filename, flags, mode"},
    6: {"name": "close", "args": "fd"},
    7: {"name": "waitpid", "args": "pid, stat_addr, options"},
    10: {"name": "unlink", "args": "pathname"},
    11: {"name": "execve", "args": "filename, argv, envp"},
    12: {"name": "chdir", "args": "filename"},
    15: {"name": "chmod", "args": "filename, mode"},
    19: {"name": "lseek", "args": "fd, offset, whence"},
    20: {"name": "getpid", "args": ""},
    23: {"name": "setuid", "args": "uid"},
    24: {"name": "getuid", "args": ""},
    33: {"name": "access", "args": "filename, mode"},
    37: {"name": "kill", "args": "pid, sig"},
    39: {"name": "mkdir", "args": "pathname, mode"},
    40: {"name": "rmdir", "args": "pathname"},
    41: {"name": "dup", "args": "fildes"},
    42: {"name": "pipe", "args": "fildes"},
    45: {"name": "brk", "args": "brk"},
    47: {"name": "getgid", "args": ""},
    49: {"name": "geteuid", "args": ""},
    50: {"name": "getegid", "args": ""},
    54: {"name": "ioctl", "args": "fd, cmd, arg"},
    63: {"name": "dup2", "args": "oldfd, newfd"},
    64: {"name": "getppid", "args": ""},
    66: {"name": "setsid", "args": ""},
    85: {"name": "readlink", "args": "path, buf, bufsiz"},
    90: {"name": "mmap", "args": "addr, len, prot, flags, fd, off"},
    91: {"name": "munmap", "args": "addr, len"},
    102: {"name": "socketcall", "args": "call, args"},
    104: {"name": "setitimer", "args": "which, value, ovalue"},
    116: {"name": "sysinfo", "args": "info"},
    119: {"name": "sigreturn", "args": ""},
    120: {"name": "clone", "args": "clone_flags, newsp, parent_tidptr, child_tidptr, tls_val"},
    122: {"name": "uname", "args": "name"},
    125: {"name": "mprotect", "args": "start, len, prot"},
    141: {"name": "getdents", "args": "fd, dirent, count"},
    146: {"name": "writev", "args": "fd, vec, vlen"},
    162: {"name": "nanosleep", "args": "rqtp, rmtp"},
    168: {"name": "poll", "args": "ufds, nfds, timeout"},
    173: {"name": "rt_sigaction", "args": "sig, act, oact, sigsetsize"},
    174: {"name": "rt_sigprocmask", "args": "how, nset, oset, sigsetsize"},
    175: {"name": "rt_sigreturn", "args": ""},
    183: {"name": "getcwd", "args": "buf, size"},
    190: {"name": "vfork", "args": ""},
    192: {"name": "mmap2", "args": "addr, len, prot, flags, fd, pgoff"},
    195: {"name": "stat64", "args": "filename, statbuf"},
    196: {"name": "lstat64", "args": "filename, statbuf"},
    197: {"name": "fstat64", "args": "fd, statbuf"},
    220: {"name": "getdents64", "args": "fd, dirent, count"},
    221: {"name": "fcntl64", "args": "fd, cmd, arg"},
    240: {"name": "futex", "args": "uaddr, op, val, utime, uaddr2, val3"},
    243: {"name": "set_thread_area", "args": "u_info"},
    252: {"name": "exit_group", "args": "error_code"},
    258: {"name": "set_tid_address", "args": "tidptr"},
    265: {"name": "clock_gettime", "args": "which_clock, tp"},
    295: {"name": "openat", "args": "dfd, filename, flags, mode"},
    300: {"name": "fstatat64", "args": "dfd, filename, statbuf, flag"},
    355: {"name": "getrandom", "args": "buf, count, flags"},
    358: {"name": "execveat", "args": "fd, filename, argv, envp, flags"},
    383: {"name": "statx", "args": "dfd, filename, flags, mask, buffer"},
}

# ═══════════════════════════════════════════════
# Linux ARM (32-bit) syscall table (common ones)
# ═══════════════════════════════════════════════

SYSCALL_ARM: dict[int, dict] = {
    1: {"name": "exit", "args": "error_code"},
    2: {"name": "fork", "args": ""},
    3: {"name": "read", "args": "fd, buf, count"},
    4: {"name": "write", "args": "fd, buf, count"},
    5: {"name": "open", "args": "filename, flags, mode"},
    6: {"name": "close", "args": "fd"},
    11: {"name": "execve", "args": "filename, argv, envp"},
    20: {"name": "getpid", "args": ""},
    37: {"name": "kill", "args": "pid, sig"},
    45: {"name": "brk", "args": "brk"},
    54: {"name": "ioctl", "args": "fd, cmd, arg"},
    63: {"name": "dup2", "args": "oldfd, newfd"},
    90: {"name": "mmap", "args": "addr, len, prot, flags, fd, off"},
    91: {"name": "munmap", "args": "addr, len"},
    120: {"name": "clone", "args": "clone_flags, newsp, parent_tidptr, child_tidptr, tls_val"},
    125: {"name": "mprotect", "args": "start, len, prot"},
    192: {"name": "mmap2", "args": "addr, len, prot, flags, fd, pgoff"},
    248: {"name": "exit_group", "args": "error_code"},
    322: {"name": "openat", "args": "dfd, filename, flags, mode"},
    384: {"name": "getrandom", "args": "buf, count, flags"},
}

# ═══════════════════════════════════════════════
# Linux AArch64 syscall table (common ones)
# ═══════════════════════════════════════════════

SYSCALL_ARM64: dict[int, dict] = {
    56: {"name": "openat", "args": "dfd, filename, flags, mode"},
    57: {"name": "close", "args": "fd"},
    62: {"name": "lseek", "args": "fd, offset, whence"},
    63: {"name": "read", "args": "fd, buf, count"},
    64: {"name": "write", "args": "fd, buf, count"},
    78: {"name": "readlinkat", "args": "dfd, pathname, buf, bufsiz"},
    79: {"name": "fstatat", "args": "dfd, filename, statbuf, flag"},
    80: {"name": "fstat", "args": "fd, statbuf"},
    93: {"name": "exit", "args": "error_code"},
    94: {"name": "exit_group", "args": "error_code"},
    96: {"name": "set_tid_address", "args": "tidptr"},
    129: {"name": "kill", "args": "pid, sig"},
    134: {"name": "rt_sigaction", "args": "sig, act, oact, sigsetsize"},
    135: {"name": "rt_sigprocmask", "args": "how, nset, oset, sigsetsize"},
    139: {"name": "rt_sigreturn", "args": ""},
    172: {"name": "getpid", "args": ""},
    174: {"name": "getuid", "args": ""},
    175: {"name": "geteuid", "args": ""},
    176: {"name": "getgid", "args": ""},
    177: {"name": "getegid", "args": ""},
    198: {"name": "socket", "args": "family, type, protocol"},
    200: {"name": "bind", "args": "fd, umyaddr, addrlen"},
    201: {"name": "listen", "args": "fd, backlog"},
    202: {"name": "accept", "args": "fd, upeer_sockaddr, upeer_addrlen"},
    203: {"name": "connect", "args": "fd, uservaddr, addrlen"},
    206: {"name": "sendto", "args": "fd, buff, len, flags, addr, addr_len"},
    207: {"name": "recvfrom", "args": "fd, ubuf, size, flags, addr, addr_len"},
    220: {"name": "clone", "args": "clone_flags, newsp, parent_tidptr, child_tidptr, tls_val"},
    221: {"name": "execve", "args": "filename, argv, envp"},
    222: {"name": "mmap", "args": "addr, len, prot, flags, fd, off"},
    226: {"name": "mprotect", "args": "start, len, prot"},
    215: {"name": "munmap", "args": "addr, len"},
    214: {"name": "brk", "args": "brk"},
    228: {"name": "madvise", "args": "start, len, behavior"},
    260: {"name": "wait4", "args": "upid, stat_addr, options, ru"},
    261: {"name": "prlimit64", "args": "pid, resource, new_rlim, old_rlim"},
    278: {"name": "getrandom", "args": "buf, count, flags"},
    281: {"name": "execveat", "args": "fd, filename, argv, envp, flags"},
    291: {"name": "statx", "args": "dfd, filename, flags, mask, buffer"},
    435: {"name": "clone3", "args": "uargs, size"},
}


SYSCALL_TABLES = {
    "x86": SYSCALL_X86,
    "x86_64": SYSCALL_X64,
    "x64": SYSCALL_X64,
    "arm": SYSCALL_ARM,
    "arm32": SYSCALL_ARM,
    "arm64": SYSCALL_ARM64,
    "aarch64": SYSCALL_ARM64,
}


def lookup_syscall(number: int, platform: str = "x86_64") -> Optional[dict]:
    """Look up a syscall by number and platform."""
    table = SYSCALL_TABLES.get(platform.lower())
    if table is None:
        return None
    entry = table.get(number)
    if entry is None:
        return None
    return {
        "number": number,
        "name": entry["name"],
        "args": entry["args"],
        "platform": platform,
    }


def lookup_syscall_by_name(name: str, platform: str = "x86_64") -> list[dict]:
    """Look up syscalls by name (partial match)."""
    table = SYSCALL_TABLES.get(platform.lower())
    if table is None:
        return []
    results = []
    for num, entry in table.items():
        if name.lower() in entry["name"].lower():
            results.append({
                "number": num,
                "name": entry["name"],
                "args": entry["args"],
                "platform": platform,
            })
    return sorted(results, key=lambda x: x["number"])


def list_all_syscalls(platform: str = "x86_64") -> list[dict]:
    """List all syscalls for a given platform."""
    table = SYSCALL_TABLES.get(platform.lower())
    if table is None:
        return []
    return [
        {"number": num, "name": entry["name"], "args": entry["args"]}
        for num, entry in sorted(table.items())
    ]


def get_available_platforms() -> list[str]:
    """Return list of supported syscall platforms."""
    return list(SYSCALL_TABLES.keys())
