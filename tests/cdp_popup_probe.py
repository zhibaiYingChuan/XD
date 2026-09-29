# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
"""桌面端 release 实测：切页时是否弹出 PowerShell 窗口。

为什么判据必须是 Win32 窗口表
────────────────────────────────────────────────────────────────
「有没有弹窗」在 UI 层完全观察不到 —— 窗口会自己消失，
等截图的人反应过来时早已不见。唯一可靠的判据是操作系统的
可见顶层窗口表：控制台窗口是真实窗口，有 class 名有标题。

★ 必须在 release 下测
  debug 构建自带控制台。父进程已有控制台时，Windows 不会再为
  powershell.exe 新建窗口 —— 弹窗问题在 debug 下**天然测不出来**。
  这正是「本地开发一切正常，发给用户就闪屏」的成因。

★ 判据不是「有没有 powershell 进程」
  CREATE_NO_WINDOW 生效时子进程照常运行，只是没有窗口。
  「有进程无窗口」是正常的；「无进程」也可能只是没触发采集。
  所以只看**可见顶层窗口**。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time
import urllib.request

EXE = os.environ.get("XUANDUN_EXE", r"G:\rust-target\release\xuandun-personal.exe")
CDP = "http://127.0.0.1:9224"
ENGINE_PORTS = (18765, 18801, 18802)

user32 = ctypes.windll.user32
user32.SetProcessDPIAware()

_CONSOLE_KEYS = ("ConsoleWindowClass", "powershell", "conhost", "cmd.exe")

# 判据自检期间拉起的探针进程，结束时逐个收掉。
#
# ★ 刻意**不**用 `taskkill /IM powershell.exe`：
#   那会连带杀掉用户自己开着的 PowerShell 窗口与正在跑的脚本。
#   测试为了自己好看，把用户的工作环境清空，是不可接受的。
_PROBE_PIDS: list[int] = []


def _kill_probes() -> None:
    for pid in _PROBE_PIDS:
        try:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        except Exception:
            pass
    _PROBE_PIDS.clear()
    time.sleep(0.8)


def visible_console_windows() -> list[str]:
    """列出当前所有可见的控制台类顶层窗口。

    ★ 回调函数必须**保住引用**。
      ctypes 的 CFUNCTYPE 对象若在 EnumWindows 返回前被 GC 回收，
      托管侧不会报错，只是回调**静默不再执行** ——
      枚举结果恒为空列表。而「空列表」正是本脚本要判定的
      「没有弹窗」，于是判据会为一个失灵的采样器背书。
      这类失败没有任何错误信息可查，只能靠判据自检暴露。
    """
    found: list[str] = []

    def _cb(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        buf = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, buf, 512)
        title = buf.value
        cbuf = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, cbuf, 256)
        cls = cbuf.value
        blob = f"{cls}|{title}"
        if any(k.lower() in blob.lower() for k in _CONSOLE_KEYS):
            found.append(blob)
        return True

    # ★ 关键：把回调对象存进局部变量并保证 EnumWindows 期间存活。
    proto = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
    keep = proto(_cb)
    user32.EnumWindows(keep, 0)
    del keep
    return found


class Sampler:
    """后台高频采样可见控制台窗口。

    ★ 必须与点击**并发**：弹窗可能只存在几百毫秒，
      串行地「点完再查」大概率已经错过。
    """

    def __init__(self, interval: float = 0.05):
        self.interval = interval
        self.hits: list[tuple[float, str]] = []
        self._stop = False

    def __enter__(self):
        import threading

        def loop():
            while not self._stop:
                for w in visible_console_windows():
                    self.hits.append((time.time(), w))
                time.sleep(self.interval)

        self._t = threading.Thread(target=loop, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop = True
        self._t.join(timeout=2)


def cdp_ready() -> bool:
    try:
        with urllib.request.urlopen(f"{CDP}/json/version", timeout=3) as r:
            return bool(r.read())
    except Exception:
        return False


def engine_health() -> dict | None:
    """探测引擎健康状态。

    ★ 端口不能只试固定几个：桌面端按 config.json 的 server.port 监听，
      而那个值是用户可改的。写死端口列表 = 用户改过端口后本探测恒为
      None，而判据随即会给出「无弹窗」的假通过 ——
      引擎没起来就不会采集机器码，也就根本不会弹窗。
    """
    import json as _json

    # 扫本机监听端口：找 /health 里有 version 的那个
    try:
        out = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=15
        ).stdout
    except Exception:
        return None
    ports = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].upper().startswith("TCP") and "LISTENING" in line.upper():
            try:
                ports.add(int(parts[1].rsplit(":", 1)[1]))
            except (ValueError, IndexError):
                pass
    for p in sorted(ports):
        if p < 1024 or p > 65535:
            continue
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{p}/health", timeout=2) as r:
                data = _json.loads(r.read().decode())
        except Exception:
            continue
        # ★ 必须凭 guard_ready 认领，不能只看「有 version 字段」。
        #   本机上还跑着 LRC 记忆服务（/health 也返回 version），
        #   只认 version 会把它当成玄盾引擎 —— 判据指向了一个
        #   与被测对象无关的服务，然后据此宣布「弹窗已修复」。
        if data.get("guard_ready") is not None and "relay_configured" in data:
            return {"port": p, **data}
    return None


def main() -> int:
    print("=" * 70)
    print("  玄盾 release 实测 — 切页是否弹出 PowerShell 窗口")
    print("=" * 70)

    if not os.path.isfile(EXE):
        print(f"[FATAL] 找不到可执行文件: {EXE}")
        return 2
    st = os.stat(EXE)
    import datetime

    print(f"  程序: {EXE}")
    print(f"  大小: {st.st_size / 1024 / 1024:.1f} MB")
    print(f"  时间: {datetime.datetime.fromtimestamp(st.st_mtime)}")
    print()

    baseline = visible_console_windows()
    print(f"  [基线] 可见控制台窗口: {len(baseline)} 个 {baseline}")
    print()

    env = os.environ.copy()
    # release 下 CDP 默认关闭（见 lib.rs::enable_cdp_debug_port）
    env["XUANDUN_ENABLE_CDP_DEBUG"] = "1"

    print("  启动桌面端…")
    proc = subprocess.Popen([EXE], env=env)

    try:
        # 等 CDP + 引擎就绪
        ok_cdp = False
        for _ in range(40):
            if cdp_ready():
                ok_cdp = True
                break
            if proc.poll() is not None:
                print(f"[FATAL] 进程提前退出，退出码 {proc.returncode}")
                return 2
            time.sleep(1)
        print(f"  CDP: {'就绪' if ok_cdp else '未就绪（无法自动点击）'}")
        if not ok_cdp:
            return 2

        # ★ 引擎是**懒启动**的：只在第一次需要它时才拉起。
        #   CDP 就绪不代表引擎已起 —— 首页加载会请求 /api/state，
        #   那才是触发点。所以必须轮询等待，不能只探一次。
        h = None
        for i in range(45):
            h = engine_health()
            if h:
                break
            if proc.poll() is not None:
                print(f"[FATAL] 等待引擎期间进程退出，退出码 {proc.returncode}")
                return 2
            time.sleep(1)
        print(f"  引擎: {h if h else '未探测到（已等待 45s）'}")

        # ★★★ 引擎不在场就**必须**判失败，绝不能继续。
        #
        #   弹窗的来源是引擎采集机器码时拉起的 powershell。
        #   引擎没起来 → 没人采集 → 没人拉 powershell → 窗口表干干净净，
        #   判据会给出一个漂亮的 PASS。
        #
        #   那是本脚本最容易犯的错：**用「没发生」冒充「没问题」**。
        #   用户看到的「已修复」与实际情况可以毫无关系。
        if h is None:
            print()
            print("  [FATAL] 引擎未运行 —— 本次测试无效。")
            print("    引擎不采集机器码就不会拉起 powershell，")
            print("    「无弹窗」是因为根本没走到那条路径，不是问题已修复。")
            return 2
        if not h.get("guard_ready"):
            print()
            print("  [FATAL] 引擎报告 guard_ready=false，检测能力降级。")
            return 2
        time.sleep(3)

        from playwright.sync_api import sync_playwright

        pages = ["首页", "日志", "设置", "帮助", "激活", "首页"]
        with sync_playwright() as pw:
            browser = pw.chromium.connect_over_cdp(CDP)
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            page.set_default_timeout(10000)

            nav = page.locator("nav a").all_inner_texts()
            print(f"  导航项: {[t.strip() for t in nav if t.strip()]}")
            print()

            print("  ── 切页测试（点击与窗口采样并发）──")
            per_page: dict[str, int] = {}
            for label in pages:
                with Sampler() as sp:
                    try:
                        link = page.locator(f"nav a:has-text('{label}')").first
                        link.click(timeout=8000)
                        page.wait_for_timeout(900)
                        status = "已切换"
                    except Exception as e:
                        status = f"点击失败 {type(e).__name__}"
                time.sleep(0.2)
                n = len(sp.hits)
                per_page[label] = n
                mark = "!! 弹出" if n else "无弹窗"
                print(f"    {label:<6} {status:<12} {mark}（采样 {n} 次）")

            # ★ 单独盯「激活」页：机器码就是在那条路径上被采集的，
            #   而采集才是弹窗的唯一来源。上面那次切到激活页已经算覆盖，
            #   这里再补一次长观察 —— 采集含 powershell 调用，可能偏慢。
            print()
            print("  ── 激活页停留 8s（机器码采集的实际发生地）──")
            try:
                page.locator("nav a:has-text('激活')").first.click(timeout=8000)
            except Exception as e:
                print(f"    点击激活页失败: {e}")
            with Sampler() as sp_act:
                page.wait_for_timeout(8000)
            print(f"    激活页期间捕获: {len(sp_act.hits)} 次")
            sp2 = sp_act

        all_hits = sp.hits + sp2.hits
        print()
        print("  ── 真实性核验：机器码真的被采集过吗 ──")
        # ★ 这是防「假通过」的最后一道。
        #   弹窗的唯一来源是引擎调 powershell 取序列号。
        #   若引擎压根没走到那一步（缓存命中、状态未变化、请求失败），
        #   窗口表当然干净 —— 但那与「修复有效」毫无关系。
        #   所以直接向引擎要机器码，并观察这一刻有没有窗口。
        try:
            port = h.get("port")
            with Sampler() as sp_v:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/license/machine_code",
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=40) as r:
                    import json as _json

                    mch = _json.loads(r.read().decode())
            # ★ 键名是驼峰 machineCode（见 app.py license_machine_code）。
            #   这正是本项目反复踩的那类契约坑：引擎按驼峰输出，
            #   取 snake_case 会静默拿到 None，而判据若不检查，
            #   就会把「没取到」当成「没有」—— 用缺失冒充通过。
            got = (
                mch.get("machineCode")
                or mch.get("machine_code_hash")
                or mch.get("machine_code")
                or ""
            )
            print(f"    引擎返回机器码: {got[:40]}{'…' if len(got) > 40 else ''}")
            print(f"    采集期间捕获窗口: {len(sp_v.hits)} 次")
            if not got:
                print("    [FATAL] 引擎没有返回机器码 —— 无法证明采集路径被走到")
                return 2
            # ★ 拿到降级串也不算走到真实路径：
            #   采集失败时 license.machine_code() 会返回
            #   "hw-unavailable:<platform>"，它同样有值、同样过了上面的判据，
            #   但 powershell 根本没被拉起 —— 弹窗路径依然没被覆盖。
            if got.startswith("hw-unavailable:"):
                print(f"    [FATAL] 机器码是降级串（{got}）")
                print("      说明 WMI 采集失败，powershell 未被拉起，弹窗路径未被覆盖")
                return 2
            all_hits += sp_v.hits
        except Exception as e:
            print(f"    [FATAL] 直接请求引擎机器码端点失败: {e}")
            print("      本次测试无效：弹窗路径是否被走到无法确认")
            return 2

        print()
        print("  ── 判据自检：确认采样器真能抓到控制台窗口 ──")
        # ★ 「没抓到」有两种可能：真的没有，或采样器失灵。
        #   只报前者就是在给自己开免罪通道 ——
        #   判据必须先证明自己有效，结论才可信。
        #
        # ★★ 探针必须用**独立进程**去弹窗，不能在本进程里 Popen。
        #
        #   2026-09-29 实测踩到的坑：本脚本自己**没有控制台**
        #   （由 IDE 沙箱以 GUI 方式拉起，GetConsoleWindow()==0）。
        #   而 subprocess 在父进程无控制台时会自动加 CREATE_NO_WINDOW，
        #   于是 Popen('powershell') 压根不弹窗 —— 探针测不到自己要测的东西，
        #   判据自检永远失败，看起来像「采样器坏了」。
        #
        #   正确做法：让一个**有控制台的**进程去启动 powershell。
        #   `cmd /c start` 会真正新建可见控制台窗口。
        probe_cmd = (
            "start \"\" /wait powershell -NoExit -Command \"Start-Sleep -Seconds 5\""
        )
        with Sampler(interval=0.03) as sp_self:
            p_self = subprocess.Popen(
                ["cmd", "/c", probe_cmd],
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _PROBE_PIDS.append(p_self.pid)
            time.sleep(3.0)
            if p_self.poll() is None:
                p_self.kill()
        probe_ok = len(sp_self.hits) > 0
        if probe_ok:
            print(f"    [OK] 采样器成功捕获自检窗口（{len(sp_self.hits)} 次）—— 判据有效")
        else:
            # 再试一次「显式要求新建控制台」的路子
            with Sampler(interval=0.03) as sp_alt:
                p_alt = subprocess.Popen(
                    [
                        "powershell",
                        "-NoExit",
                        "-Command",
                        "Start-Sleep -Seconds 5",
                    ],
                    creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
                )
                _PROBE_PIDS.append(p_alt.pid)
                time.sleep(3.0)
            if sp_alt.hits:
                print(f"    [OK] 采样器捕获自检窗口（{len(sp_alt.hits)} 次，CREATE_NEW_CONSOLE）")
                probe_ok = True

        if not probe_ok:
            _kill_probes()
            print("    [FATAL] 采样器连故意弹出的窗口都抓不到 —— 判据失灵")
            print("      本次「无弹窗」结论无效，不能作为修复证据")
            return 2

        # 自检窗口留着会干扰后续采样，也留在用户桌面上 —— 只收探针自己。
        _kill_probes()

        print()
        print("  ── 结论 ──")
        if not all_hits:
            print("  [PASS] 全程未捕获任何可见控制台窗口 —— 弹窗问题已修复")
            return 0
        print(f"  [FAIL] 捕获 {len(all_hits)} 次控制台窗口:")
        seen = set()
        for ts, w in all_hits[:12]:
            if w in seen:
                continue
            seen.add(w)
            print(f"    · {w}")
        return 1
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=8)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        time.sleep(1)
        subprocess.run(
            ["taskkill", "/F", "/IM", "xuandun-engine-amd64-pc-windows-msvc.exe"],
            capture_output=True,
        )


if __name__ == "__main__":
    sys.exit(main())
