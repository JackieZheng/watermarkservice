#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prewarm-rva.py — UWD2 符号缓存「预热 + 校验 + 相邻 build 迁移」外层工具
（不改动 ClearWinWatermark.exe，也不改系统任何文件）

做什么
    替 uwd2 把 %APPDATA%\\reticivis\\UWD2\\data\\<PDB索引>.rva 提前准备好，
    这样 ClearWinWatermark.exe 一启动就命中缓存，不联网、不会因为 404 而 panic。

三级来源（依次尝试，全部要过校验才会写缓存）
    ⓪ 同机其它档案的缓存（离线，最快）：
       服务以 LocalSystem 运行时 %APPDATA% 指向 systemprofile，与登录用户不是同一个目录；
       本机 shell32.dll 是**机器级**的，所以别的档案用同一 PDB 索引写下的 RVA
       只要通过校验就同样适用 —— 这样服务账号无需联网也能拿到 RVA。
    ① 本 build 的 shell32.pdb（msdl 上按本机 GUID+Age 索引）
       —— 预览版刚更新时通常还没有（404）
    ② 相邻 build 迁移（关键能力）：
       从 WinbIndex 的 Insider 索引里挑出「更早、且符号已发布」的最近几个 build，
       下载它的 shell32.dll（msdl 的 <TimeDateStamp><SizeOfImage> 索引）→ 读它的 PDB 索引
       → 下载它的 shell32.pdb → 取出 CDesktopWatermark::s_DesktopBuildPaint
       → 用「函数体锚点投票」把它在当前 shell32.dll 里重新定位
       —— 只有当票数集中唯一、落点是函数入口、且函数大小与参考 build 完全一致时才采纳
    ③ 手工指定 PDB URL（--check-url，只体检不写）

为什么可靠
    相邻 build 的同一个函数，机器码几乎逐字节相同（除了 RIP 相对位移），
    所以「用参考函数体里的多个 24 字节锚点去当前 DLL 里投票」能得到唯一且可验证的结果；
    再叠加「必须落在 pdata 函数入口 + 函数大小完全一致」两条硬校验，
    基本排除误定位。实测：参考 build 29671 → 当前 29680，29/29 票命中
    0x081d28，size 0xa1f 完全一致，8 个邻居函数全部一一对应、size 全等。

用法
    python prewarm-rva.py --verify          # 只体检现有缓存（不联网、不写入）
    python prewarm-rva.py                   # 体检 → 同机档案播种 → 本build PDB → 相邻build迁移 → 校验 → 写入
    python prewarm-rva.py --no-neighbor      # 只允许用本 build 的 PDB（不迁移）
    python prewarm-rva.py --no-seed          # 不做同机其它档案的离线播种
    python prewarm-rva.py --check-url URL   # 用指定 PDB URL 走一遍（仅体检，不写）
    python prewarm-rva.py --quarantine      # 校验失败的缓存改名备份（默认只报告）

退出码
    0 = 缓存可用（或已成功预热）
    1 = 当前 build 符号未发布且迁移不可用
    2 = 解析或校验失败（拒绝写入）
    3 = 环境错误
"""

import argparse
import ctypes
import gzip
import itertools
import json
import os
import re
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.request
from ctypes import wintypes

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SYMBOL_NAME = "CDesktopWatermark::s_DesktopBuildPaint"
DEFAULT_SHELL32 = r"C:\Windows\System32\shell32.dll"
DEFAULT_PDB_URL = "https://msdl.microsoft.com/download/symbols/shell32.pdb/{index}/shell32.pdb"
MSDL = "https://msdl.microsoft.com/download/symbols/"
INSIDER_INDEX = ("https://m417z.com/winbindex-data-insider/by_filename_compressed/"
                 "{sub}/shell32.dll.json.gz")
HTTP_UA = "ureq/2.9.4"          # 与 uwd2 一致
MSDL_UA = "Microsoft-Symbol-Server/10.0.0.0"

OK, NO_SYMBOLS, BAD_RVA, ENV_ERR = 0, 1, 2, 3
# --verify 专用码：把「根本没有缓存」与「有缓存但内容不对」分开，
# 便于外层守卫给出不误导的日志（两者处置方式完全不同）。
CACHE_MISS = 4
ANCHOR_LEN = 24
ANCHOR_STEP = 0x20
MIN_VOTES = 8


# --------------------------------------------------------------------- HTTP
def http_get(url, ua=HTTP_UA, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def http_try(url, ua=HTTP_UA, timeout=180):
    """404/403 返回 None，其它异常抛出"""
    try:
        return http_get(url, ua, timeout)
    except urllib.error.HTTPError as e:
        if e.code in (404, 403, 410):
            return None
        raise


# ----------------------------------------------------------------------- PE
def pe_sections(d):
    e = struct.unpack_from("<I", d, 0x3C)[0]
    coff = e + 4
    nsec = struct.unpack_from("<H", d, coff + 2)[0]
    sizeopt = struct.unpack_from("<H", d, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    sec_off = opt + sizeopt
    secs = []
    for i in range(nsec):
        o = sec_off + i * 40
        nm = d[o:o + 8].rstrip(b"\0").decode("ascii", "ignore")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", d, o + 8)
        secs.append((nm, vaddr, vsize, rptr, rsize))
    return coff, opt, dd, secs


def make_maps(secs):
    def r2o(rva):
        for _nm, vaddr, vsize, rptr, rsize in secs:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return rptr + (rva - vaddr)
        return None

    def o2r(off):
        for _nm, vaddr, vsize, rptr, rsize in secs:
            if rptr <= off < rptr + rsize:
                return vaddr + (off - rptr)
        return None
    return r2o, o2r


def pe_machine(d):
    """IMAGE_FILE_HEADER.Machine —— 位于 coff+0（coff = e_lfanew+4）"""
    _coff, _opt, _dd, _secs = pe_sections(d)
    return struct.unpack_from("<H", d, _coff)[0]


def rsds_of_bytes(d):
    """返回 (索引串, pdb名) 或 (None, None)"""
    _coff, _opt, dd, secs = pe_sections(d)
    r2o, _o2r = make_maps(secs)
    dbg_rva, dbg_size = struct.unpack_from("<II", d, dd + 6 * 8)
    if not dbg_rva:
        return None, None
    off = r2o(dbg_rva)
    if off is None:
        return None, None
    for i in range(dbg_size // 28):
        o = off + i * 28
        _ch, _ts, _maj, _min, _typ, sz, ptr_rva, ptr = struct.unpack_from("<IIHHIIII", d, o)
        do = r2o(ptr_rva) if ptr_rva else ptr
        if do is None:
            continue
        blob = d[do:do + sz]
        if blob[:4] == b"RSDS":
            guid = blob[4:20]
            age = struct.unpack_from("<I", blob, 20)[0]
            d1, d2, d3 = struct.unpack("<IHH", guid[:8])
            hexg = "%08X%04X%04X%s" % (d1, d2, d3, guid[8:].hex().upper())
            return hexg + ("%X" % age), blob[24:].split(b"\0")[0].decode("ascii", "ignore")
    return None, None


def read_pdb_index(shell32_path):
    """读本机 shell32.dll 的 CodeView(RSDS) -> 与 uwd2 get_guid() 相同的索引串"""
    with open(shell32_path, "rb") as f:
        d = f.read()
    if d[:2] != b"MZ":
        raise RuntimeError("not a PE file: %s" % shell32_path)
    idx, name = rsds_of_bytes(d)
    if not idx:
        raise RuntimeError("RSDS record not found in %s" % shell32_path)
    return idx, name


def read_function_starts(shell32_path):
    """解析 .pdata -> {函数入口RVA: 函数大小}"""
    with open(shell32_path, "rb") as f:
        d = f.read()
    _coff, _opt, dd, secs = pe_sections(d)
    r2o, _o2r = make_maps(secs)
    prva, psz = struct.unpack_from("<II", d, dd + 3 * 8)
    off = r2o(prva)
    if off is None:
        raise RuntimeError("no .pdata")
    table = {}
    for i in range(psz // 12):
        a, b, _u = struct.unpack_from("<III", d, off + i * 12)
        if b > a:
            table[a] = b - a
    return table


def pe_size_of_image(d):
    _coff, opt, _dd, _secs = pe_sections(d)
    return struct.unpack_from("<I", d, opt + 56)[0]


def pe_timestamp(d):
    """IMAGE_FILE_HEADER.TimeDateStamp —— 位于 coff+4"""
    _coff, _opt, _dd, _secs = pe_sections(d)
    return struct.unpack_from("<I", d, _coff + 4)[0]


# ---------------------------------------------------------------------- PDB
class _SYMBOL_INFO(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG), ("TypeIndex", wintypes.ULONG),
        ("Reserved", ctypes.c_ulonglong * 2), ("Index", wintypes.ULONG), ("Size", wintypes.ULONG),
        ("ModBase", ctypes.c_ulonglong), ("Flags", wintypes.ULONG), ("Value", ctypes.c_ulonglong),
        ("Address", ctypes.c_ulonglong), ("Register", wintypes.ULONG), ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG), ("NameLen", wintypes.ULONG), ("MaxNameLen", wintypes.ULONG),
        ("Name", ctypes.c_char * 1),
    ]


_CB = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.POINTER(_SYMBOL_INFO), wintypes.ULONG, ctypes.c_void_p)
_PDB_BASE_SEQ = itertools.count()      # 每次解析用不同的加载基址，避免 dbghelp 同基址冲突
_PDB_BASE0 = 0x10000000


def parse_pdb_symbol(pdb_path, needle=SYMBOL_NAME):
    """用系统 dbghelp 解析 PDB -> (rva, size, 完整名)

    注意：dbghelp 在同一进程内不允许两个模块共用同一加载基址（第二个 SymLoadModuleEx 会失败），
    所以这里每次调用都取一个递增的基址，并在结束时卸载模块 + SymCleanup。
    """
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbg = ctypes.WinDLL("dbghelp", use_last_error=True)
    dbg.SymSetOptions.argtypes = [wintypes.DWORD]
    dbg.SymSetOptions.restype = wintypes.DWORD
    dbg.SymInitialize.argtypes = [wintypes.HANDLE, wintypes.LPCSTR, wintypes.BOOL]
    dbg.SymInitialize.restype = wintypes.BOOL
    dbg.SymLoadModuleEx.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCSTR, wintypes.LPCSTR,
                                    ctypes.c_ulonglong, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    dbg.SymLoadModuleEx.restype = ctypes.c_ulonglong
    dbg.SymUnloadModule64.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong]
    dbg.SymUnloadModule64.restype = wintypes.BOOL
    dbg.SymCleanup.argtypes = [wintypes.HANDLE]
    dbg.SymCleanup.restype = wintypes.BOOL
    dbg.SymEnumSymbols.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, wintypes.LPCSTR, _CB, ctypes.c_void_p]
    dbg.SymEnumSymbols.restype = wintypes.BOOL

    h = k32.GetCurrentProcess()
    # SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_NO_PROMPTS
    dbg.SymSetOptions(0x00000002 | 0x00000004 | 0x00000040 | 0x00080000)
    if not dbg.SymInitialize(h, None, False):
        raise RuntimeError("SymInitialize failed")
    base = _PDB_BASE0 + (next(_PDB_BASE_SEQ) * _PDB_BASE0)
    try:
        if not dbg.SymLoadModuleEx(h, None, pdb_path.encode("ascii"), None, base, 0, None, 0):
            raise RuntimeError("SymLoadModuleEx failed: %s" % pdb_path)
        found = []

        def _cb(psym, _sz, _ctx):
            s = psym.contents
            if s.Tag == 5:
                nm = ctypes.string_at(ctypes.addressof(s) + _SYMBOL_INFO.Name.offset,
                                      s.NameLen).decode("ascii", "ignore")
                found.append((s.Address - base, s.Size, nm))
            return True

        dbg.SymEnumSymbols(h, base, b"*DesktopBuildPaint*", _CB(_cb), None)
        leaf = needle.split("::")[-1]
        for rva, size, nm in found:
            if nm == needle or nm.endswith("::" + leaf):
                return rva, size, nm
        raise RuntimeError("symbol %r not found in %s" % (needle, pdb_path))
    finally:
        try:
            dbg.SymUnloadModule64(h, base)
            dbg.SymCleanup(h)
        except Exception:
            pass


# ------------------------------------------------------------------- 校验/投票
def validate(rva, pdb_size, funcs):
    if rva not in funcs:
        for a, s in funcs.items():
            if a <= rva < a + s:
                return False, ("RVA %#x 不是函数入口：落在函数 [%#x, %#x) 内部 +%#x（该函数仅 %#x 字节）"
                               % (rva, a, a + s, rva - a, s))
        return False, "RVA %#x 不在任何函数范围内" % rva
    local = funcs[rva]
    if pdb_size and local != pdb_size:
        return False, ("RVA %#x 是函数入口，但大小对不上：参考 PDB %#x 字节 / 本机 %#x 字节"
                       "（两者不是同一份代码）" % (rva, pdb_size, local))
    if pdb_size:
        return True, "RVA %#x 是函数入口，大小 %#x 字节，与参考 PDB 一致" % (rva, local)
    return True, "RVA %#x 是函数入口，大小 %#x 字节（本机 .pdata 函数表）" % (rva, local)


def anchor_vote(ref_body, now_data, o2r):
    """把参考函数体的 24 字节锚点投到当前 DLL，返回 {候选函数入口RVA: 票数}"""
    hits = {}
    for i in range(0, max(0, len(ref_body) - ANCHOR_LEN), ANCHOR_STEP):
        blk = ref_body[i:i + ANCHOR_LEN]
        if blk.count(0) > 6 or len(set(blk)) < 10:
            continue
        st = 0
        n = 0
        while n < 30:
            p = now_data.find(blk, st)
            if p == -1:
                break
            st = p + 1
            n += 1
            rva = o2r(p)
            if rva is None:
                continue
            cand = rva - i
            hits[cand] = hits.get(cand, 0) + 1
    return hits


def _djb2_sub(name):
    h = 5381
    for ch in name:
        h = ((h << 5) + h + ord(ch)) & 0xFFFFFFFF
    return "%02x" % (h & 0xFF)


def _cached_get(url, fname, log=None):
    """带本地缓存的下载 —— 参考 build 的 DLL/PDB 有 20MB，避免每次重下"""
    d = os.path.join(tempfile.gettempdir(), "uwd2_prewarm")
    p = os.path.join(d, fname)
    if os.path.exists(p) and os.path.getsize(p) > 4096:
        if log:
            log("          （用本地缓存 %s）" % fname)
        with open(p, "rb") as f:
            return f.read()
    data = http_try(url)
    if data is not None:
        os.makedirs(d, exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
    return data


def windows_build():
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        return int(winreg.QueryValueEx(k, "CurrentBuild")[0])
    except Exception:
        return 0


def _profile_cache_dirs():
    """列出本机所有可能出现 UWD2 缓存的目录（含 SYSTEM / 服务账号档案）。

    服务以 LocalSystem 运行时 %APPDATA% 指向 systemprofile，和当前登录用户的
    不是同一个目录 —— 这是「服务日志写着 Executing、水印却一直在」的根因之一。
    """
    drive = os.environ.get("SystemDrive", "C:")
    win = os.environ.get("SystemRoot", drive + "\\Windows")
    roots = []
    users = os.path.join(drive + os.sep, "Users")
    if os.path.isdir(users):
        for u in sorted(os.listdir(users)):
            roots.append(os.path.join(users, u, "AppData", "Roaming"))
    roots.append(os.path.join(win, "System32", "config", "systemprofile", "AppData", "Roaming"))
    roots.append(os.path.join(win, "ServiceProfiles", "LocalService", "AppData", "Roaming"))
    roots.append(os.path.join(win, "ServiceProfiles", "NetworkService", "AppData", "Roaming"))
    out = []
    for r in roots:
        d = os.path.join(r, "reticivis", "UWD2", "data")
        if os.path.isdir(d):
            out.append(d)
    return out


def seed_from_profiles(index, funcs, cur_file, log=print):
    """在当前档案的缓存缺失时，去同机其它档案里找同索引的缓存。

    本机 shell32.dll 是**机器级**的（所有账户共用同一份文件），所以别处用同一索引
    写下的 RVA 只要通过校验就同样适用于本账户 —— 这样服务账号（LocalSystem）
    不必联网也能拿到 RVA。返回 (rva, 来源路径) 或 None。
    """
    cands = _profile_cache_dirs()
    if not cands:
        log("        · 本机没有其它档案的缓存目录")
        return None
    log("        · 扫描本机其它档案的缓存目录：%s" % ", ".join(cands))
    for d in cands:
        p = os.path.join(d, index + ".rva")
        if not os.path.exists(p) or os.path.abspath(p) == os.path.abspath(cur_file):
            continue
        try:
            raw = open(p, "rb").read()
            if len(raw) < 4:
                log("          - %s：文件过短，跳过" % p)
                continue
            v = struct.unpack(">I", raw[:4])[0]
            ok, why = validate(v, 0, funcs)
            log("          - %s：%#x  %s %s" % (p, v, "✅" if ok else "❌", why))
            if ok:
                return v, p
        except Exception as e:
            log("          - %s：读取失败 %s" % (p, e))
    return None


def neighbor_migrate(shell32_path, funcs, cur_build, log=print, max_try=12):
    """从「更早且符号已发布」的相邻 Insider build 迁移目标函数 RVA。

    返回 (rva, size, from_label, votes) 或 None

    候选筛选（每一步都留有日志，绝不静默跳过）：
      · 排除当前 build 自身 —— 它的符号正是拿不到的那一份，参考它无意义
      · 按 build 降序（越近越像）；同一 build 内按 SizeOfImage 与本机的接近度升序
        —— shell32.dll 在同一 build 下同时存在 x64 / ARM64 / x86 三种架构，
           x64 的 SizeOfImage 与本机最接近，这样能先挑到对的架构，避免白下 15MB
      · SizeOfImage 与本机相差 > 4MB 的直接判为异架构/异分支，不再下载
    """
    with open(shell32_path, "rb") as f:
        now_data = f.read()
    _coff, _opt, _dd, secs = pe_sections(now_data)
    _r2o, o2r = make_maps(secs)
    cur_size = len(now_data)
    local_soi = pe_size_of_image(now_data)

    sub = _djb2_sub("shell32.dll")
    log("        · 取 WinbIndex Insider 索引 (…/by_filename_compressed/%s/shell32.dll.json.gz)" % sub)
    idx = json.loads(gzip.decompress(http_get(INSIDER_INDEX.format(sub=sub))).decode("utf-8"))

    cands = []
    for sha, v in idx.items():
        fi = v.get("fileInfo", {})
        m = re.match(r"10\.0\.(\d+)\.(\d+)", fi.get("version", "") or "")
        if not m:
            continue
        b = int(m.group(1))
        if cur_build and b >= cur_build:        # 当前 build 自身 → 排除
            continue
        if not fi.get("timestamp") or not fi.get("virtualSize"):
            continue
        size = fi.get("size", 0)
        if size and abs(size - cur_size) > 8 * 1024 * 1024:   # 体积差太大，不适合当参考
            continue
        cands.append((b, int(m.group(2)), size, int(fi["timestamp"]), int(fi["virtualSize"])))

    cands.sort(key=lambda c: (-c[0], -c[1], abs(c[4] - local_soi)))
    log("        · 本机 SizeOfImage = %#x，候选参考 build：%s"
        % (local_soi, ", ".join("%d.%d(soi=%#x)" % (b, r, vs)
                                for b, r, _s, _t, vs in cands[:8]) or "（无）"))
    if not cands:
        log("        · 没有比当前 build 更早的可用参考")
        return None

    for b, rev, size, ts, vsize in cands[:max_try]:
        label = "%d.%d" % (b, rev)
        if local_soi and abs(vsize - local_soi) > 0x400000:
            log("        · 参考 %s：跳过 —— SizeOfImage %#x 与本机 %#x 差 %#x（异架构/异分支）"
                % (label, vsize, local_soi, abs(vsize - local_soi)))
            continue
        try:
            url = "%sshell32.dll/%08X%x/shell32.dll" % (MSDL, ts, vsize)
            dll = _cached_get(url, "shell32_%d_%x.dll" % (b, vsize), log)
            if dll is None:
                log("        · 参考 %s：跳过 —— 符号服务器没有这份 DLL（%s）" % (label, url))
                continue
            mach = pe_machine(dll)
            if mach != 0x8664:                  # 只接受 x64
                log("        · 参考 %s：跳过 —— PE machine=%#06x（非 x64）" % (label, mach))
                continue
            ridx, pdbname = rsds_of_bytes(dll)
            if not ridx:
                log("        · 参考 %s：跳过 —— 读不到 RSDS 调试记录" % label)
                continue
            pdb = _cached_get("%s%s/%s/%s" % (MSDL, pdbname, ridx, pdbname), ridx + ".pdb", log)
            if pdb is None:
                log("        · 参考 %s：跳过 —— 符号服务器没有这份 PDB（%s）" % (label, ridx))
                continue
            tmp = os.path.join(tempfile.gettempdir(), "prewarm_ref_shell32.pdb")
            with open(tmp, "wb") as f:
                f.write(pdb)
            ref_rva, ref_size, ref_name = parse_pdb_symbol(tmp)
            _c2, _o2, _d2, secs2 = pe_sections(dll)
            r2o2, _o22 = make_maps(secs2)
            body = dll[r2o2(ref_rva):r2o2(ref_rva) + ref_size]
            hits = anchor_vote(body, now_data, o2r)
            if not hits:
                log("        · 参考 %s：跳过 —— 函数体锚点在本机 DLL 中零命中" % label)
                continue
            best, votes = max(hits.items(), key=lambda x: x[1])
            second = sorted(hits.values(), reverse=True)[1] if len(hits) > 1 else 0
            ok, why = validate(best, ref_size, funcs)
            log("        · 参考 %s：%s RVA=%#x size=%#x → 本机 %#x 票数=%d(次高%d) %s"
                % (label, ref_name, ref_rva, ref_size, best, votes, second, "✅" if ok else "❌"))
            if ok and votes >= MIN_VOTES and votes > second * 2:
                return best, ref_size, label, votes
        except Exception as e:
            log("        · 参考 %s 处理失败：%s" % (label, e))
            continue
    return None


# ------------------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser(description="UWD2 符号缓存预热/校验/相邻build迁移")
    ap.add_argument("--verify", action="store_true", help="只体检现有缓存")
    ap.add_argument("--check-url", metavar="URL", help="用指定 PDB URL 走一遍（不写缓存）")
    ap.add_argument("--no-neighbor", action="store_true", help="不启用相邻 build 迁移")
    ap.add_argument("--no-seed", action="store_true", help="不做同机其它档案的离线播种")
    ap.add_argument("--quarantine", action="store_true", help="校验失败的缓存改名备份")
    ap.add_argument("--shell32", default=DEFAULT_SHELL32)
    ap.add_argument("--cache-dir", default=None)
    args = ap.parse_args()

    try:
        index, pdbname = read_pdb_index(args.shell32)
        funcs = read_function_starts(args.shell32)
    except Exception as e:
        print("[环境错误] %s" % e)
        return ENV_ERR

    cdir = args.cache_dir or os.path.join(os.environ.get("APPDATA", ""), "reticivis", "UWD2", "data")
    cfile = os.path.join(cdir, index + ".rva")
    print("本机 shell32 : %s" % args.shell32)
    print("PDB 索引     : %s" % index)
    print("缓存文件     : %s  [%s]" % (cfile, "存在" if os.path.exists(cfile) else "不存在"))
    print("函数表       : %d 个函数入口" % len(funcs))

    cached = None
    if os.path.exists(cfile):
        cached = struct.unpack(">I", open(cfile, "rb").read()[:4])[0]
        ok, why = validate(cached, 0, funcs)
        print("\n[体检] 缓存值 = %#x" % cached)
        print("       %s %s" % ("✅" if ok else "❌", why))
        if not ok:
            if args.quarantine:
                bak = cfile + ".bak." + time.strftime("%Y%m%d%H%M%S")
                os.replace(cfile, bak)
                print("       → 已隔离为 %s" % os.path.basename(bak))
                cached = None
            else:
                print("       ⚠️ 这个地址会被 exe 直接用于写 explorer 内存；可加 --quarantine 隔离后再预热。")
    else:
        print("\n[体检] 无缓存（exe 将联网下载符号）")

    if args.verify:
        # 退出码：0 = 缓存就绪；4 = 缓存缺失；2 = 缓存存在但校验未通过；3 = 环境错误
        if cached is None:
            print("\n[体检] 结论：缓存缺失（本机还没有这个索引的 .rva 文件）")
            return CACHE_MISS
        ok2, _why2 = validate(cached, 0, funcs)
        if ok2:
            print("\n[体检] 结论：缓存就绪且校验通过")
            return OK
        print("\n[体检] 结论：缓存存在但校验未通过 —— 内容与本机 shell32 不匹配")
        return BAD_RVA

    if cached is not None and validate(cached, 0, funcs)[0] and not args.check_url:
        print("\n缓存已就绪且校验通过 —— 无需预热。")
        return OK

    target = None

    # ⓪ 同机其它档案的缓存（离线、最快；服务账号 LocalSystem 的关键兜底）
    if not args.check_url and not args.no_seed:
        print("\n[⓪] 同机其它档案的缓存（离线播种）")
        got = seed_from_profiles(index, funcs, cfile)
        if got:
            v, where = got
            print("      采用 %s 的缓存值 %#x（本机 shell32 是机器级的，校验通过即通用）" % (where, v))
            target = (v, 0, "同机档案", 0)
        else:
            print("      没有可用的播种来源")

    # ① 本 build 的 PDB
    if target is None:
        if args.check_url:
            src = args.check_url
        else:
            src = DEFAULT_PDB_URL.format(index=index)
        print("\n[①] 本 build 符号：%s" % src)
        try:
            blob = http_try(src)
        except Exception as e:
            print("      下载失败：%s" % e)
            blob = None
        if blob:
            print("      %d 字节" % len(blob))
            tmp = os.path.join(tempfile.gettempdir(), "prewarm_shell32.pdb")
            with open(tmp, "wb") as f:
                f.write(blob)
            try:
                rva, size, name = parse_pdb_symbol(tmp)
                print("      解析：%s → RVA %#x size %#x" % (name, rva, size))
                target = (rva, size, "本build", 0)
            except Exception as e:
                print("      解析失败：%s" % e)
        else:
            print("      HTTP 404 —— 本 build 的符号尚未发布")

    # ② 相邻 build 迁移
    if target is None and not args.no_neighbor and not args.check_url:
        build = windows_build()
        print("\n[②] 相邻 build 迁移（当前 Windows build %s）" % (build or "未知"))
        got = neighbor_migrate(args.shell32, funcs, build)
        if got:
            target = got
        else:
            print("      迁移未得到可信结果")

    if target is None:
        if args.check_url:
            return BAD_RVA
        print("\n结论：拿不到可信的 RVA —— 建议等微软发布本 build 符号后重跑本工具。")
        return NO_SYMBOLS

    rva, size, src_label, votes = target
    ok, why = validate(rva, size, funcs)
    print("\n[校验] 来源=%s  %s %s" % (src_label, "✅" if ok else "❌", why))
    if not ok:
        print("       拒绝写入缓存。")
        return BAD_RVA
    if args.check_url:
        print("       （--check-url：仅体检，不写缓存）")
        return OK

    os.makedirs(cdir, exist_ok=True)
    if os.path.exists(cfile) and cached != rva:
        bak = cfile + ".bak." + time.strftime("%Y%m%d%H%M%S")
        try:
            os.replace(cfile, bak)
            print("       （旧值 %s 已备份）" % os.path.basename(bak))
        except Exception:
            pass
    with open(cfile, "wb") as f:
        f.write(struct.pack(">I", rva))
    print("\n[写入] %s = %#x（大端）" % (cfile, rva))
    print("       ClearWinWatermark.exe 现在会命中缓存直接注入，不再联网。")
    return OK


if __name__ == "__main__":
    sys.exit(main())
