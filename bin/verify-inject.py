#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify-inject.py —— 直接读 explorer 进程内存，验证 UWD2 的注入是否真的落到目标函数

做法（不依赖任何截图/肉眼）：
  1) 枚举 explorer.exe 进程，用 EnumProcessModules 找到它加载的 shell32.dll 基址；
  2) ReadProcessMemory 读 基址 + RVA 处的头 16 字节；
  3) UWD2 的注入方式是把该处第一个字节写成 0xC3 (RET)，
     所以 0xC3 = 已注入生效，其余 = 尚未注入。

用法:
  python verify-inject.py                 # 用缓存里的 RVA
  python verify-inject.py --rva 0x81d28   # 指定 RVA
  python verify-inject.py --watch         # 每 2 秒打印一次，观察前后变化

退出码（严格模式，默认）:
  0 = 已注入（首字节 0xC3）
  1 = 未注入（首字节非 0xC3）
  2 = 探测失败（找不到 explorer / 未加载 shell32 / 读内存失败）
  3 = 环境错误（需要 64 位 Python / 拿不到 RVA）
加 --no-strict 可退回旧语义：只要成功读到内存就返回 0。
"""
import argparse
import ctypes
import os
import struct
import sys
import time
from ctypes import wintypes

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03
MAX_PATH = 260

RET_BYTE = 0xC3

OK, NOT_INJECTED, PROBE_FAIL, ENV_ERR = 0, 1, 2, 3


def find_pids(name="explorer.exe"):
    arr = (wintypes.DWORD * 4096)()
    need = wintypes.DWORD()
    if not psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(need)):
        raise RuntimeError("EnumProcesses failed")
    n = need.value // ctypes.sizeof(wintypes.DWORD)
    out = []
    for i in range(n):
        pid = arr[i]
        if not pid:
            continue
        h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            continue
        try:
            buf = ctypes.create_unicode_buffer(MAX_PATH)
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(wintypes.DWORD(MAX_PATH))):
                if os.path.basename(buf.value).lower() == name.lower():
                    out.append((pid, buf.value))
        finally:
            k32.CloseHandle(h)
    return out


def modules(pid):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise RuntimeError("OpenProcess(%d) failed err=%d" % (pid, ctypes.get_last_error()))
    try:
        arr = (ctypes.c_void_p * 1024)()
        need = wintypes.DWORD()
        if not psapi.EnumProcessModulesEx(h, ctypes.byref(arr), ctypes.sizeof(arr),
                                         ctypes.byref(need), LIST_MODULES_ALL):
            raise RuntimeError("EnumProcessModulesEx failed")
        n = need.value // ctypes.sizeof(ctypes.c_void_p)
        res = []
        for i in range(n):
            base = arr[i] or 0
            buf = ctypes.create_unicode_buffer(MAX_PATH)
            if psapi.GetModuleFileNameExW(h, ctypes.c_void_p(base), buf, MAX_PATH):
                res.append((base, buf.value))
        return h, res
    except Exception:
        k32.CloseHandle(h)
        raise


def read_bytes(h, addr, n=16):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got))
    if not ok:
        raise RuntimeError("ReadProcessMemory(%#x) failed err=%d" % (addr, ctypes.get_last_error()))
    return buf.raw[:got.value]


def cached_rva():
    p = os.path.join(os.environ.get("APPDATA", ""), "reticivis", "UWD2", "data")
    if not os.path.isdir(p):
        return None, None
    for f in sorted(os.listdir(p)):
        if f.endswith(".rva"):
            b = open(os.path.join(p, f), "rb").read()
            if len(b) >= 4:
                return struct.unpack(">I", b[:4])[0], f
    return None, None


def probe(rva):
    """返回 (首字节 or None, 状态字符串)。状态字符串描述为什么读不到。"""
    try:
        procs = find_pids("explorer.exe")
    except Exception as e:
        print("枚举进程失败          : %s" % e)
        return None, "no-explorer"
    if not procs:
        print("找不到 explorer.exe")
        return None, "no-explorer"

    pid, path = procs[0]
    try:
        h, mods = modules(pid)
    except Exception as e:
        print("pid=%d 打开模块列表失败: %s" % (pid, e))
        return None, "read-fail"

    try:
        hit = [(b, p) for b, p in mods if os.path.basename(p).lower() == "shell32.dll"]
        if not hit:
            print("pid=%d 未加载 shell32.dll" % pid)
            return None, "no-shell32"
        base, mpath = hit[0]
        try:
            blob = read_bytes(h, base + rva, 16)
        except Exception as e:
            print("读内存失败            : %s" % e)
            return None, "read-fail"
        first = blob[0]
        verdict = ("✅ 已注入（首字节 0xC3 = RET）" if first == RET_BYTE else
                   "❌ 尚未注入（首字节 %#04x）" % first)
        print("explorer pid     : %d" % pid)
        print("shell32 模块     : %s" % mpath)
        print("模块基址         : %#018x" % base)
        print("探测地址         : %#018x  (= 基址 + RVA %#x)" % (base + rva, rva))
        print("头 16 字节       : %s" % " ".join("%02x" % b for b in blob))
        print("判定             : %s" % verdict)
        return first, "ok"
    finally:
        k32.CloseHandle(h)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rva", default=None, help="十六进制 RVA，如 0x81d28")
    ap.add_argument("--watch", action="store_true")
    ap.add_argument("--no-strict", action="store_true",
                    help="旧语义：只要读到内存就返回 0（不区分是否已注入）")
    a = ap.parse_args()

    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[错误] 必须用 64 位 Python 才能读 64 位 explorer 的内存")
        return ENV_ERR

    if a.rva:
        rva = int(a.rva, 16)
        src = "命令行指定"
    else:
        rva, name = cached_rva()
        src = "缓存 %s" % name if rva is not None else None
    if rva is None:
        print("[错误] 拿不到 RVA：缓存里没有 .rva 文件，也没给 --rva")
        return ENV_ERR
    print("RVA 来源         : %s" % src)
    print("-" * 52)

    if not a.watch:
        first, st = probe(rva)
        if st != "ok":
            return PROBE_FAIL
        if a.no_strict:
            return OK
        return OK if first == RET_BYTE else NOT_INJECTED

    while True:
        probe(rva)
        print("-" * 52)
        time.sleep(2)


if __name__ == "__main__":
    sys.exit(main())
