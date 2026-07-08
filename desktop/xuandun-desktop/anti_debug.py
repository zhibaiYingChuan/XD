# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

import ctypes
import ctypes.wintypes
import hashlib
import logging
import os
import struct
import subprocess
import sys
import time

logger = logging.getLogger("xuandun.anti_debug")

# macOS sysctl 常量
_CTL_KERN = 1
_KERN_PROC = 1
_KERN_PROC_PID = 14
_P_TRACED = 0x800


def _check_is_debugger_present() -> bool:
    if sys.platform != "win32":
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        if kernel32.IsDebuggerPresent():
            logger.warning("Debugger detected: IsDebuggerPresent")
            return True
    except Exception:
        pass
    return False


def _check_remote_debugger() -> bool:
    if sys.platform != "win32":
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        debugged = ctypes.wintypes.BOOL(False)
        kernel32.CheckRemoteDebuggerPresent(
            kernel32.GetCurrentProcess(),
            ctypes.byref(debugged),
        )
        if debugged:
            logger.warning("Debugger detected: CheckRemoteDebuggerPresent")
            return True
    except Exception:
        pass
    return False


def _check_nt_query() -> bool:
    if sys.platform != "win32":
        return False
    try:
        ntdll = ctypes.windll.ntdll
        debug_port = ctypes.c_ulonglong(0)
        status = ntdll.NtQueryInformationProcess(
            -1,
            7,
            ctypes.byref(debug_port),
            ctypes.sizeof(debug_port),
            None,
        )
        if debug_port.value != 0:
            logger.warning("Debugger detected: NtQueryInformationProcess (debug port)")
            return True
    except Exception:
        pass
    return False


def _check_windows_debugger_processes() -> bool:
    """Windows: EnumProcesses 扫描 x64dbg/ida/Windbg/Frida/Process Hacker。"""
    if sys.platform != "win32":
        return False
    debugger_names = (
        "x64dbg.exe", "x32dbg.exe", "ollydbg.exe",
        "ida.exe", "ida64.exe", "windbg.exe",
        "frida.exe", "processhacker.exe", "cheatengine-x86_64.exe",
        "cheatengine-i386.exe",
    )
    try:
        psapi = ctypes.windll.psapi
        kernel32 = ctypes.windll.kernel32
        count = 1024
        pids = (ctypes.wintypes.DWORD * count)()
        cb = ctypes.sizeof(pids)
        bytes_returned = ctypes.wintypes.DWORD()
        if not psapi.EnumProcesses(ctypes.byref(pids), cb, ctypes.byref(bytes_returned)):
            return False
        pid_count = bytes_returned.value // ctypes.sizeof(ctypes.wintypes.DWORD)
        for i in range(pid_count):
            pid = pids[i]
            h = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFO | VM_READ
            if not h:
                continue
            try:
                name_buf = ctypes.create_unicode_buffer(260)
                if psapi.GetModuleBaseNameW(h, None, name_buf, 260):
                    if name_buf.value.lower() in debugger_names:
                        logger.warning("Debugger process detected: %s (pid=%d)", name_buf.value, pid)
                        return True
            finally:
                kernel32.CloseHandle(h)
    except Exception:
        pass
    return False


def _check_macos_ptrace() -> bool:
    """macOS: ptrace(PT_DENY_ATTACH) 防附加。已附加调试器时调用失败。"""
    if sys.platform != "darwin":
        return False
    try:
        libc = ctypes.CDLL("/usr/lib/system/libsystem_kernel.dylib")
        PT_DENY_ATTACH = 31
        libc.ptrace(PT_DENY_ATTACH, 0, 0, 0)
    except Exception:
        logger.warning("Debugger detected: ptrace(PT_DENY_ATTACH) failed")
        return True
    return False


def _check_macos_sysctl() -> bool:
    """macOS: sysctl 查询 kinfo_proc.kp_proc.p_flag 的 P_TRACED 标志。"""
    if sys.platform != "darwin":
        return False
    try:
        libc = ctypes.CDLL("/usr/lib/libc.dylib")
        # kinfo_proc 在 64 位 macOS 约 648 字节，分配足够大缓冲区
        buf_size = 648
        buf = ctypes.create_string_buffer(buf_size)
        size = ctypes.c_size_t(buf_size)
        mib = (ctypes.c_int * 4)(_CTL_KERN, _KERN_PROC, _KERN_PROC_PID, os.getpid())
        result = libc.sysctl(mib, 4, buf, ctypes.byref(size), None, 0)
        if result != 0:
            return False
        # extern_proc 布局（64 位）：p_start(16) + p_vmspace(8) + p_sigacts(8) = 32 偏移处为 p_flag
        if size.value < 36:
            return False
        p_flag = struct.unpack_from("i", buf.raw, 32)[0]
        if p_flag & _P_TRACED:
            logger.warning("Debugger detected: sysctl P_TRACED")
            return True
    except Exception:
        pass
    return False


def _check_linux_tracer_pid() -> bool:
    """Linux: 读 /proc/self/status 的 TracerPid。"""
    if sys.platform != "linux" or not os.path.exists("/proc/self/status"):
        return False
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    pid = int(line.split(":")[1].strip())
                    if pid != 0:
                        logger.warning("Debugger detected: TracerPid=%d", pid)
                        return True
                    break
    except Exception:
        pass
    return False


def _check_linux_debugger_processes() -> bool:
    """Linux: 扫描 /proc/*/exe 匹配 gdb/lldb/frida/ida。"""
    if sys.platform != "linux":
        return False
    debugger_names = ("gdb", "lldb", "frida-server", "ida", "ida64", "strace", "ltrace")
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            exe_link = f"/proc/{entry}/exe"
            try:
                target = os.readlink(exe_link).lower()
                if any(name in target for name in debugger_names):
                    logger.warning("Debugger process detected: %s (pid=%s)", target, entry)
                    return True
            except OSError:
                continue
    except Exception:
        pass
    return False


def _check_timing() -> bool:
    t0 = time.perf_counter()
    _ = sum(i * i for i in range(10000))
    elapsed = time.perf_counter() - t0
    if elapsed > 0.1:
        logger.warning("Timing anomaly detected: %.3fs for simple computation", elapsed)
        return True
    return False


def is_memory_dump_attempt() -> bool:
    if sys.platform != "win32":
        return False
    try:
        procdump_names = ["procdump.exe", "procdump64.exe", "minidump.exe"]
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq procdump.exe"],
            capture_output=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout = result.stdout.decode("utf-8", errors="ignore")
        for name in procdump_names:
            if name.lower() in stdout.lower():
                logger.warning("Memory dump tool detected: %s", name)
                return True
    except Exception:
        pass
    return False


def verify_binary_integrity() -> bool:
    """校验玄盾核心模块文件的完整性。

    检测逻辑：
    - Nuitka 编译后（sys.executable 包含 xuandun）：校验 sys.executable
    - 开发模式：校验同目录下关键 .py 文件的 SHA-256
    - 首次运行（无哈希文件）：输出警告并跳过校验
    - 哈希文件存储在 ~/.xuandun/sig/ 下，权限 0600，防覆写
    """
    try:
        is_nuitka = (
            hasattr(sys, "frozen")
            or os.environ.get("NUITKA_ONEFILE_PARENT")
            or "xuandun" in os.path.basename(sys.executable).lower()
        )

        if is_nuitka:
            return _verify_executable()
        else:
            return _verify_source_files()
    except Exception:
        return True


def _get_hash_file_path(filename: str) -> str:
    """哈希文件存 ~/.xuandun/sig/，权限 0600，防覆写。"""
    home = os.path.expanduser("~")
    sig_dir = os.path.join(home, ".xuandun", "sig")
    os.makedirs(sig_dir, exist_ok=True)
    safe_name = filename.replace(os.sep, "_").replace(":", "_")
    hash_file = os.path.join(sig_dir, f"{safe_name}.sha256")
    if not os.path.exists(hash_file):
        open(hash_file, "w").close()
        try:
            os.chmod(hash_file, 0o600)
        except Exception:
            pass  # Windows chmod 语义不同，忽略
    return hash_file


def _compute_file_hash(filepath: str) -> str:
    """计算文件的 SHA-256 哈希。"""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_executable() -> bool:
    """校验 Nuitka 编译后的可执行文件完整性。"""
    exe_path = sys.executable
    if not exe_path or not os.path.exists(exe_path):
        return True

    current_hash = _compute_file_hash(exe_path)
    hash_file = _get_hash_file_path(os.path.basename(exe_path))

    if os.path.exists(hash_file):
        with open(hash_file, "r") as f:
            expected_hash = f.read().strip()
        if not expected_hash:
            with open(hash_file, "w") as f:
                f.write(current_hash)
            logger.info("Baseline hash written for %s", exe_path)
            return True
        if current_hash != expected_hash:
            logger.error("Binary integrity check FAILED: hash mismatch for %s", exe_path)
            return False
        return True

    logger.warning("No baseline hash found for %s, skipping integrity check", exe_path)
    return True


def _verify_source_files() -> bool:
    """校验源码模式下关键 .py 文件的完整性。"""
    this_dir = os.path.dirname(os.path.abspath(__file__))
    critical_files = ["engine_flask.py", "anti_debug.py"]

    all_ok = True
    for filename in critical_files:
        filepath = os.path.join(this_dir, filename)
        if not os.path.exists(filepath):
            logger.warning("Critical file not found, skipping: %s", filepath)
            continue

        current_hash = _compute_file_hash(filepath)
        hash_file = _get_hash_file_path(filename)

        if os.path.exists(hash_file):
            with open(hash_file, "r") as f:
                expected_hash = f.read().strip()
            if not expected_hash:
                with open(hash_file, "w") as f:
                    f.write(current_hash)
                logger.info("Baseline hash written for %s", filepath)
                continue
            if current_hash != expected_hash:
                logger.error("Integrity check FAILED: hash mismatch for %s", filepath)
                all_ok = False
        else:
            logger.warning("No baseline hash found for %s, skipping integrity check", filepath)

    return all_ok


def is_debugger_present() -> bool:
    # Windows 检测
    if _check_is_debugger_present():
        return True
    if _check_remote_debugger():
        return True
    if _check_nt_query():
        return True
    if _check_windows_debugger_processes():
        return True
    if is_memory_dump_attempt():
        return True
    # macOS 检测
    if _check_macos_ptrace():
        return True
    if _check_macos_sysctl():
        return True
    # Linux 检测
    if _check_linux_tracer_pid():
        return True
    if _check_linux_debugger_processes():
        return True
    # 通用时序检测
    if _check_timing():
        return True
    return False


def run_checks() -> int:
    if is_debugger_present():
        return 1
    if not verify_binary_integrity():
        return 2
    return 0
