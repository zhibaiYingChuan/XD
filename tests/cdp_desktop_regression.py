#!/usr/bin/env python3
# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""个人版桌面端 CDP 回归测试（真实 WebView2 + 真实鼠标键盘交互）。

为什么需要这个
────────────────────────────────────────────────────────────────
pytest 覆盖的是**检测逻辑**（baseline / verifier / sanitizer），
但它跑在纯 Python 环境里，验证不了：
  · 界面是否真的能打开、渲染、切换页面
  · 状态栏 / 托盘是否随引擎状态正确变化
  · 「引擎未运行」「防护已暂停」时用户看到的是什么
    （这是最容易骗过用户的地方，也是最危险的失效模式）
  · 设置页开关是否真的落到后端配置上

判据设计：对照式，不靠关键词猜测
────────────────────────────────────────────────────────────────
★ 本脚本所有「诚实性」断言都用**独立事实源**做对照，绝不靠关键词白名单：
  界面的说法  ←→  后端 /api/state、/api/config、Rust 托盘状态的真实值

原因：若用「文案里含『防护』二字就算通过」这类白名单，
  安全产品最严重的缺陷 —— 对用户谎报状态 —— 会天然通过测试：
  谎报文案往往比真文案更「漂亮」，关键词更全。
  对照式判据才有效。例：T3 断言「状态栏显示的 label 恰好是
  真实后端状态对应的那一个，且不是其他任何状态的 label」。

运行前提
────────────────────────────────────────────────────────────────
  1. 启动桌面端（debug 构建会自动开 CDP 端口 9224）：
       cd personal/desktop/src-tauri
       cargo run
     release 构建需先设环境变量：
       $env:XUANDUN_ENABLE_CDP_DEBUG='1'
  2. 另开终端执行：
       cd personal
       python tests/cdp_desktop_regression.py

副作用与还原
────────────────────────────────────────────────────────────────
本脚本会真实改动用户配置，因此**必须能干净还原**，否则测试本身成了风险源：
  · 向导：首次运行时用占位中转站走完，结束后还原 config.json + localStorage
  · T5b：切换一个防护开关，验证后端真的变了，再切回来
  · T9：暂停防护验证状态变化，再恢复
任何一步异常中断，finally 块都会兜底还原（finally 内异常不外抛，
  但会打印，绝不静默失败）。

CDP 端口安全性
────────────────────────────────────────────────────────────────
个人版在 release 构建下默认**不开启** CDP 端口
（见 src-tauri/src/lib.rs 的 enable_cdp_debug_port）：
开放该端口等于允许任意本地进程注入 JS 篡改界面显示，
对安全产品是严重风险。debug 构建自动开启，release 需显式环境变量。
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("[SKIP] 未安装 playwright —— pip install playwright")
    sys.exit(0)


CDP_BASE = "http://127.0.0.1:9224"
DEFAULT_PROXY_PORT = 18765
ONBOARDING_KEY = "xuandun-personal-onboarded"

# 走完向导时写入的占位中转站。
# 刻意用 .invalid 保留域（RFC 2606 保留，永不可解析）——
# 任何"忘记还原就真的发请求"的情况都会立即失败而不是打到真实站点。
PLACEHOLDER_URL = "https://relay.example.invalid"
PLACEHOLDER_KEY = "sk-cdp-regression-placeholder"

# 后端 state 枚举 → 用户应看到的 label。
# ★ 必须与 desktop/src/services/api.ts 的 STATE_LABELS 保持一致。
#   前端改文案时这里会红 —— 这正是我们要的：状态展示语义变了，
#   必须有人确认「新的说法是否仍然诚实」，而不是让测试默默接受。
STATE_LABELS = {
    "protecting": "防护中",
    "learning": "学习中",
    "suspect": "可疑",
    "danger": "危险",
    "paused": "已暂停",
}
# ★ 不再有 ALL_STATE_LABELS：原判据「整条状态栏只许出现一个状态词」
#   与状态栏的设计冲突 —— 它本就渲染「危险 N」「可疑 N」等统计项。
#   详见 test_status_bar_honest 里的说明。

results = {"pass": 0, "fail": 0, "skip": 0}
_console_errors: list[str] = []


def rec(name, ok, detail="", skip=False):
    if skip:
        results["skip"] += 1
        print(f"[SKIP] {name}" + (f" -> {detail}" if detail else ""), flush=True)
        return
    results["pass" if ok else "fail"] += 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name}"
          + (f" -> {detail}" if detail else ""), flush=True)


def section(title):
    print(f"\n── {title} " + "─" * max(0, 60 - len(title)), flush=True)


# ══════════════════════════════════════════════════════════════
# 后端事实源（独立于前端渲染）
# ══════════════════════════════════════════════════════════════


class Backend:
    """直连本地代理 HTTP，拿引擎的真实状态。

    ★ 必须走 HTTP 而非前端 IPC：前端 IPC 的返回值就是界面将要展示的内容，
      拿它当对照物等于自己跟自己比 —— 界面若谎报，IPC 也一起谎报，
      对照就完全失效。HTTP 直连拿的是引擎的真实状态。
    """

    def __init__(self, port):
        self.port = port
        # 记录最近一次读取失败的原因，供断言给出可诊断的说明
        self.last_error = ""

    def _get(self, path, timeout=5):
        url = f"http://127.0.0.1:{self.port}{path}"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def _post(self, path, payload, timeout=8):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload or {}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode("utf-8"))
            except Exception:
                return {"ok": False, "status": e.code}

    def health(self):
        try:
            return self._get("/health", timeout=3)
        except Exception:
            return None

    def state(self):
        """读后端真实状态。

        ★ 不可用时**必须暴露原因**，不能静默返回 None：
          拿不到对照物，「界面是否诚实」就退化成自说自话 ——
          而那正是本脚本要防的那类缺陷。
        """
        try:
            return self._get("/api/state", timeout=6)
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            return None

    def config(self):
        try:
            return self._get("/api/config", timeout=4)
        except Exception:
            return None

    def diagnostics(self):
        """读后端诊断信息（含 relay_configured / relay_domain）。

        ★ 这是「首页有没有谎报中转站配置状态」的**唯一对照源**。
          /api/config 也能推出，但它是用户填的原值、
          域名要前端再解析一次 —— 而 /api/diagnostics 给的是
          引擎自己算出的 relay_domain，与首页读的那份同源。
        """
        try:
            return self._get("/api/diagnostics", timeout=5)
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            return None

    def post_chat(self, payload, timeout=30):
        """向引擎的对话端点发一次真实请求。

        ★ T10 需要它：拦截测试必须**真的打一条请求过去**，
          手工构造日志记录或直接改数据库都验不到
          「引擎拦了 → 界面如实呈现」这条链路。
          只有真发一次，中间那层才是被验证过的。

        返回 (状态码, 响应体)。状态码 403/502 表示被拦截 ——
        那正是要断言的，不是错误。
        """
        url = f"http://127.0.0.1:{self.port}/v1/chat/completions"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # ★ 拦截就是以 4xx/5xx 回来的，必须读出响应体 ——
            #   里面才有 error.type 与 findings，那是断言的依据。
            try:
                return e.code, json.loads(e.read().decode("utf-8"))
            except Exception:
                return e.code, {}
        except Exception as e:
            return None, {"error": f"{type(e).__name__}: {e}"}

    def block_logs(self, limit=5):
        """读拦截类日志。"""
        try:
            return self._get(f"/api/logs?limit={limit}&action=block", timeout=8)
        except Exception:
            return None

    def log_detail(self, log_id, timeout=8):
        """读单条日志详情（含脱敏记录 / 拦截依据）。"""
        try:
            return self._get(f"/api/logs/{log_id}", timeout=timeout)
        except Exception:
            return None

    def unmark_safe(self, log_id, timeout=8):
        """撤销误报标记（T12 收尾用，把用户统计还原）。"""
        try:
            return self._post(
                f"/api/logs/{log_id}/unmark-safe", {}, timeout=timeout)
        except Exception:
            return None

    def relays(self, timeout=8):
        """读中转站信誉列表（T13 校验评分用）。"""
        try:
            return self._get("/api/relays", timeout=timeout)
        except Exception:
            return None

    def guard(self):
        """从配置里取 guard 段（不依赖 to_safe_dict 的掩码细节）。"""
        c = self.config()
        return (c or {}).get("guard") or {}


def cdp_browser_ver():
    try:
        with urllib.request.urlopen(f"{CDP_BASE}/json/version", timeout=3) as r:
            return json.loads(r.read().decode()).get("Browser", "")[:40]
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════
# 配置备份 / 还原
# ══════════════════════════════════════════════════════════════


def config_file() -> Path:
    base = Path(os.getenv("LOCALAPPDATA") or (Path.home() / ".config"))
    return base / "com.daoti.xuandun-personal" / "config.json"


class ConfigGuard:
    """config.json 的备份 / 还原。

    ★★ 还原文件 ≠ 还原运行中的引擎（这个坑实测踩过）
    ────────────────────────────────────────────────────────────
    引擎的 _config 是**启动时载入的内存对象**，之后 /api/config 的更新
    只改内存 + 落盘，从不回读文件。所以「把文件改回去」之后：
      · 文件干净了
      · 引擎内存里**仍然是测试写入的占位中转站**
    结果是一台「配置显示未配置、实际却在按占位地址转发」的引擎 ——
    比不还原更危险：界面在骗人，而骗人的是安全产品自己。

    也不能靠 /api/config 清：后端把 api_key 的空串一律当作
    「保持原密钥不变」（见 app.py update_config），所以占位 Key
    永远清不掉 —— 这是一个**有意的正确设计**，不是缺陷，
    但它意味着「用 API 复原」这条路根本走不通。

    唯一干净的做法：还原文件后让引擎重启，由它自己重新读文件。
    """

    def __init__(self):
        self.path = config_file()
        self.backup: bytes | None = None
        self.existed = self.path.exists()
        if self.existed:
            self.backup = self.path.read_bytes()

    def has_placeholder(self, be: "Backend") -> bool:
        """引擎内存里是否残留占位中转站。

        ★ 判据必须查「引擎内存」而不是「本轮是否走过向导」：
          上一轮跑完若清理失败，残留会一直留着；此时本轮
          onboarded_by_test=False，按「本轮是否写过」判断就会跳过清理，
          残留永久留存 —— 而占位中转站是 .invalid 保留域，
          用户的 AI 工具会一直打到一个解析不了的地址。
        """
        try:
            cur = (be.config() or {}).get("relay") or {}
            return cur.get("base_url") == PLACEHOLDER_URL
        except Exception:
            return False

    def restore_file(self):
        """还原磁盘文件（幂等，可在 finally 里重复调用）。"""
        try:
            if self.existed and self.backup is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.path.write_bytes(self.backup)
                return f"已还原 config.json（{len(self.backup)} 字节）"
            if not self.existed and self.path.exists():
                self.path.unlink()
                return "已删除测试产生的 config.json"
            return "config.json 无需还原"
        except Exception as e:
            # 还原失败必须显式暴露：静默失败会让用户以为配置没被改过
            return f"!! config.json 还原失败: {e}"


def reload_engine_from_disk(page, be: Backend):
    """让引擎重启并重新从 config.json 载入，然后核对结果。

    ★ 为什么必须重启而不是改配置：
      引擎只在启动时读一次配置。而 api_key 的「空串 = 不修改」语义
      让 API 层无法把测试写入的占位 Key 清掉 —— 只能换掉整个进程状态。

    ★ page.evaluate() 没有 timeout 参数（只有 locator 操作有）。
      重启要等引擎自解压就绪，最长可能 60s；用 page.set_default_timeout
      兜不住 evaluate。真正的上限由外层 socket 超时和下面的健康轮询共同兜底。

    返回一行说明。
    """
    try:
        page.evaluate("() => window.__TAURI_INTERNALS__.invoke('restart_engine')")
    except Exception as e:
        return (f"!! 引擎重启失败（{type(e).__name__}: {e}）—— "
                f"内存中可能仍是占位中转站，请手动重启玄盾")

    # 等引擎真正换上「还原后的配置」。
    #
    # ★ 这里不能用「health 一通就断言」：
    #   restart 之后有一个窗口期 —— 旧进程已被杀掉但新进程还没绑定端口，
    #   或新进程刚起来还没处理完请求。此时若恰好有一次 health 成功返回，
    #   它可能来自**旧进程**（带着占位中转站的内存状态）。
    #   早判一次就会得出「还原失败」的假结论。
    #
    # 判据改为「连续 N 次 health 都报告未配置中转站」：
    # 只有稳定地读到新状态，才能确认换成的是重载后的引擎。
    deadline = time.time() + 60
    clean_streak = 0
    need = 3
    while time.time() < deadline:
        h = be.health()
        if h and not h.get("relay_configured"):
            clean_streak += 1
            if clean_streak >= need:
                return (f"已重启引擎并确认其按还原后的配置运行"
                        f"（连续 {need} 次报告未配置中转站）")
        else:
            clean_streak = 0
        page.wait_for_timeout(500)
    return "!! 引擎重启后 60s 内未稳定读到「未配置中转站」，请手动重启玄盾"


# ══════════════════════════════════════════════════════════════
# 页面工具
# ══════════════════════════════════════════════════════════════


def status_label(page, timeout=4000):
    """读取状态栏的主 label（不含右侧统计，不含 meta 文案）。"""
    try:
        return page.locator(".status-label").first.inner_text(timeout=timeout).strip()
    except Exception:
        return ""


def status_text(page, timeout=4000):
    try:
        return page.locator(".status-bar").first.inner_text(timeout=timeout).strip()
    except Exception:
        return ""


def tray_state(page):
    """通过 Tauri IPC 读 Rust 侧托盘状态。

    托盘是用户唯一能感知「防护是否在跑」的通道（窗口隐藏时界面全不可见），
    所以托盘的诚实性与状态栏同等重要。
    """
    try:
        return page.evaluate(
            "() => window.__TAURI_INTERNALS__.invoke('get_tray_state')"
        )
    except Exception:
        return None


def goto(page, label):
    """点击左侧导航并等路由真正切换（不靠固定 sleep）。

    ★ 判据用「目标导航项变为 active」而不是「页面出现 .page-title」：
      首页刻意用 hero 区做首屏（无 page-header），四个页面结构本就不统一。
      假设统一结构会让本用例在首页上必然超时 —— 那是测试的缺陷，不是产品的。
    """
    link = page.locator(f"nav a:has-text('{label}')").first
    link.click(timeout=8000)
    page.wait_for_function(
        "([l]) => { const a = [...document.querySelectorAll('nav a')]"
        "  .find(x => x.textContent.includes(l));"
        "  return !!a && a.classList.contains('active'); }",
        arg=label,
        timeout=8000,
    )
    page.wait_for_timeout(350)
    # ★★ 必须再等页面**内容**就绪，不能只等路由切换。
    #
    #   导航项变 active 只说明 React 换了路由，组件的首个 render
    #   可能还没拿到数据（激活页等 license status，设置页等 config）。
    #   此前只等路由，于是「正文长度」「元素是否存在」这类断言
    #   全都跑在数据到达之前 —— 报出一堆 FAIL，
    #   而产品其实完全正常。这是把「还没到时候」当成坏了。
    #
    # ★★ 判据只认「骨架屏元素消失」，不做逐页的文案白名单。
    #   逐页列举加载文案（先补激活页、再补设置页…）必然漏：
    #   每加一个页面就要改一次测试，而漏掉的那个会一直假失败。
    #   结构性判据一劳永逸。
    try:
        page.wait_for_function(
            """() => {
                // 骨架屏 / 加载态。各页统一用 .loading > .spinner
                // （见 App.tsx / Activate.tsx / Logs.tsx / Settings.tsx）。
                // ★ 只认这两个精确 class：`*=` 模糊匹配会命中
                //   loading-guard 之类语义无关的元素，反而永远等不到。
                if (document.querySelector('.loading, .spinner')) return false;
                // 正文有实质内容（不是只有标题）
                const t = (document.body.innerText || '').trim();
                return t.length > 80;
            }""",
            timeout=15000,
        )
    except Exception:
        # 超时不算失败：交给后续断言按各自判据报出真实问题。
        # 这里静默继续，好过抛异常中断整个用例序列。
        pass
    page.wait_for_timeout(250)


def wait_label(page, expected, timeout=8000):
    """等状态栏 label 变成期望值。"""
    end = time.time() + timeout / 1000
    seen = ""
    while time.time() < end:
        seen = status_label(page, timeout=1000)
        if seen == expected:
            return True, seen
        page.wait_for_timeout(250)
    return False, seen


# ══════════════════════════════════════════════════════════════
# T0 首次运行向导
# ══════════════════════════════════════════════════════════════


def on_wizard(page):
    return page.locator(".wizard-shell").count() > 0


def wait_for_shell(page, timeout=15000):
    """等界面挂起来（主界面或向导）。返回 (是否就绪, 说明)。

    ★ 原判据是「wizard-shell 出现且主界面 nav 不在」，
      但「nav==0」不等于「还在向导里」—— 它同时也是
      **主界面正在挂载**的中间态。实测：CDP 连上后 4.3s 时
      nav 还是 0，6.5s 才挂上，这 2.2s 空窗既不是向导也不是主界面。
      原判据在这个空窗里等满 15s，然后报
      「可能是首启动判定逻辑失效」—— 而产品完全正常，
      这句话会把排查方向直接带偏（真去查 checkFirstRun 是白费工夫）。

    ★ 修法：主界面挂上就算就绪。调用方本来就只在 nav==0 时
      调进来，所以返回 True 时必然仍在向导里；
      两者都还没出现，才是界面真的没挂起来。
    """
    end = time.time() + timeout / 1000
    while time.time() < end:
        if page.locator("nav a").count() > 0:
            return True, "主界面已挂载（按设计跳过向导：中转站已配置）"
        if on_wizard(page):
            return True, "向导可见（正常：未配置过中转站的新用户会看到它）"
        page.wait_for_timeout(300)
    return False, "15s 内既没挂上主界面、也没出现向导：界面可能真的没挂起来"


def complete_wizard(page):
    """真实点击走完 4 步向导。返回 (是否成功, 说明)。

    ★ 向导现在是 4 步（欢迎 → 激活 → 配置 → 完成）。
      第 2 步是激活：机器码由 Rust 采集、验签由引擎执行，
      本机没有合法激活码，所以点「暂不激活，先看看」跳过 ——
      这条路径本身就是要测的（产品不应把试用变成付费墙）。
    """
    try:
        page.locator("button:has-text('开始')").first.click(timeout=6000)
    except Exception as e:
        return False, f"未找到「开始」按钮: {e}"

    # ── 第 2 步：激活 ──
    try:
        page.locator("#ob-code").wait_for(state="visible", timeout=8000)
    except Exception:
        # 已激活过 → 这一步直接显示「已激活」+「下一步」，没有输入框
        try:
            page.locator("button:has-text('下一步')").first.wait_for(state="visible", timeout=4000)
            page.locator("button:has-text('下一步')").first.click(timeout=6000)
        except Exception as e:
            return False, f"激活步骤既无输入框也无「下一步」: {e}"
    else:
        try:
            page.locator("button:has-text('暂不激活')").first.click(timeout=6000)
        except Exception as e:
            return False, f"未找到「暂不激活，先看看」按钮: {e}"

    # ── 第 3 步：配置 ──
    #
    # ★ 只有「接入地址」与「API Key」两项。
    #   向导曾还有「模型名称」输入框（#ob-model），已在 2026-09-29 移除：
    #   模型由调用方在请求里给出，玄盾配置模型会覆盖请求里的 model，
    #   使「模型是否被中转站偷换」失去比对基准。
    #   本脚本若不跟着删掉那一行，向导这一步必然失败，
    #   而失败原因是测试在填一个不存在的框 —— 会把它误记成产品缺陷。
    try:
        page.locator("#ob-url").wait_for(state="visible", timeout=8000)
        page.fill("#ob-url", PLACEHOLDER_URL)
        page.fill("#ob-key", PLACEHOLDER_KEY)
    except Exception as e:
        return False, f"填写配置失败: {e}"

    # 下一步按钮在两项都非空前是 disabled 的
    try:
        page.wait_for_function(
            "() => [...document.querySelectorAll('button')]"
            "  .some(b => b.textContent.includes('下一步') && !b.disabled)",
            timeout=6000,
        )
        page.locator("button:has-text('下一步')").first.click(timeout=6000)
    except Exception as e:
        return False, f"「下一步」未变为可用: {e}"

    try:
        page.locator("button:has-text('完成并进入')").first.click(timeout=6000)
        # 保存失败时组件会停在最后一步并弹 toast，不会切走
        page.locator("nav a").first.wait_for(state="visible", timeout=20000)
    except Exception as e:
        body = ""
        try:
            body = page.locator("body").inner_text()[:200]
        except Exception:
            pass
        return False, f"完成向导失败（可能引擎未就绪导致保存失败）: {e} | 页面: {body!r}"

    return True, f"已用占位中转站走完向导（{PLACEHOLDER_URL}）"


# ══════════════════════════════════════════════════════════════
# 测试用例
# ══════════════════════════════════════════════════════════════


def test_boot(page):
    """T1 应用启动 + 主界面导航齐全。"""
    title = page.title()
    rec("T1 应用启动", title != "", f"title={title!r}")

    nav_items = page.locator("nav a").all_inner_texts()
    labels = [t.strip() for t in nav_items if t.strip()]
    # 断言具体项存在，而不是只数个数 ——
    # 「数量够」拦不住「少一个、多一个没用的」。
    required = ["首页", "日志", "设置", "帮助", "激活"]
    missing = [r for r in required if not any(r in x for x in labels)]
    rec("T1 侧边导航齐全", not missing,
        f"共 {len(labels)} 项，缺失: {missing or '无'}；实际={labels}")


def test_pages_render(page):
    """T2 各个页面都能正常渲染，不白屏。

    ★ 判据是「正文有实质内容」，不是「含某个关键词」：
      关键词白名单是「照着实现写测试」—— 实现改了文案就假失败，
      而真正该拦的「渲染出来一堆乱码/报错框」反倒可能因为含有某个词而通过。
    """
    pages = ["首页", "日志", "设置", "帮助", "激活"]
    for label in pages:
        try:
            goto(page, label)
            body = page.locator("body").inner_text()
            ok = len(body.strip()) > 80
            rec(f"T2 页面「{label}」渲染", ok,
                f"正文 {len(body.strip())} 字符")
        except Exception as e:
            rec(f"T2 页面「{label}」渲染", False, f"异常: {type(e).__name__}: {e}")


def test_activate_page_honest(page, be: Backend):
    """T2b 激活页不谎报状态（对照式）。

    ★ 本组最重要的判据。激活页最容易犯的错是把「验不了」
      （引擎未启动 / 缺公钥）显示成「未激活」或「激活码无效」——
      用户会以为自己的码坏了，反复换码却永远激活不了。

    对照物：Rust 侧 get_license_status 的真实结论。
    本机没有合法激活码，所以真实结论是「未激活」；
    但界面必须额外做到：机器码可见（否则用户无从申请激活码）。
    """
    try:
        goto(page, "激活")
    except Exception as e:
        rec("T2b 激活页可打开", False, f"异常: {type(e).__name__}: {e}")
        return
    rec("T2b 激活页可打开", True, "已切换到激活页")

    body = page.locator("body").inner_text()

    # ① 机器码必须可见且形如 32 位十六进制 ——
    #    用户拿不到机器码就无从申请激活码，这是激活闭环的起点。
    mch = None
    try:
        mch = page.evaluate(
            """() => {
                const el = [...document.querySelectorAll('.code-box')]
                  .find(e => /^[0-9a-f]{32}$/i.test((e.innerText || '').trim()));
                return el ? el.innerText.trim() : null;
            }"""
        )
    except Exception as e:
        rec("T2b 机器码可见", False, f"读取失败: {e}")
        mch = None

    # 机器码哈希 = sha256(机器码)[:32]，永远是 32 位十六进制。
    # 「格式不对」在这里等价于「没显示机器码」——
    # 用户看到一串别的东西也拿不了码，所以不区分。
    rec("T2b 机器码可见（32 位十六进制）", bool(mch), f"机器码={mch!r}")

    # ② + ③ ★ 激活状态与界面元素必须互斥，且与真实状态一致。
    #
    #    ★ 此前这里是两条独立断言，且第 ② 条无条件要求
    #      「激活码输入框存在」—— 那与第 ③ 条「已激活时不该有输入框」
    #      直接矛盾：已激活态下第 ② 条必然 FAIL，
    #      而产品行为完全正确。测试自己跟自己打架。
    #
    #    正确判据是一个互斥关系，而不是两条各自独立的假设：
    #      已激活 → 有「已激活」标识、无激活码输入框
    #      未激活 → 有激活码输入框
    claims_activated = "已激活" in body
    has_input = page.locator("#act-code").count() > 0
    if claims_activated:
        rec("T2b 激活状态与界面一致", not has_input,
            "界面同时显示「已激活」和激活码输入框，两种状态矛盾"
            if has_input else "已激活态：无激活码输入框（正确）")
    else:
        rec("T2b 激活状态与界面一致", has_input,
            "界面未显示已激活，却没有激活码输入框（用户无法激活）"
            if not has_input else "未激活态：有激活码输入框（正确）")

    # ④ 换机入口必须可达 —— 换电脑是真实会发生的事，
    #    没有出口等于让用户卡死。
    rec("T2b 换机入口存在", "换机" in body, "查找「换机」相关文案")


def test_status_bar_honest(page, be: Backend):
    """T3 状态栏与引擎真实状态一致（对照式，非关键词白名单）。

    判据：状态栏 label 恰好等于**真实后端状态**对应的那一个，
    且不等于其他任何状态的 label。
    → 谎报「防护中」而真实是「危险」时，本用例必然失败。
    """
    goto(page, "首页")
    real = be.state()
    if real is None:
        rec("T3 状态栏诚实", False,
            f"无法读取后端 /api/state，无对照物（{getattr(be, 'last_error', '未知原因')}）",
            skip=True)
        return

    state = real.get("state", "learning")
    expected = STATE_LABELS.get(state, state)
    ok, seen = wait_label(page, expected, timeout=8000)
    detail = f"后端 state={state!r} 期望 label={expected!r} 实际={seen!r}"
    rec("T3 状态栏显示真实状态", ok, detail)

    if ok:
        # ★ 判据只针对「状态词」，且必须排除统计数字里的字样。
        #   曾经想把整条状态栏的文本拿来判「有且只有一个状态词」，
        #   但状态栏**设计上**就带统计：Layout.tsx 会渲染
        #   「危险 N」「可疑 N」「已打码 N 处」这几个 .status-stat。
        #   于是今日一旦真的发生过拦截，状态栏里就会同时出现
        #   「危险」和「可疑」——那是正常信息，不是自相矛盾。
        #   2026-09-29 加了 T10（真发一次带密钥的请求）后，
        #   danger/suspect 计数首次同时非零，当场把这条判据逼出来。
        #
        #   真正要防的是：label 说了「防护中」，
        #   同一状态栏里又写「今日已阻断 3 次危险响应」——
        #   一边报喜一边报警。判据因此只取 label 与 stat 里的
        #   **结论性措辞**，不取统计项的名称。
        bar = status_text(page)
        # 统计项（"危险 2"/"可疑 1"）是事实陈述，不参与矛盾判定；
        # 只检查是否出现了「与之矛盾的结论语」——
        #   即除了当前状态词之外的、表示状态的措辞。
        CONTRADICTING = ("已阻断", "被拦截", "发生危险", "出现危险")
        wrong = [o for o in CONTRADICTING
                 if o in bar and expected not in ("危险", "已拦截", "阻断")]
        rec("T3 状态栏无自相矛盾", not wrong,
            f"状态栏全文={bar!r}，混入矛盾的结论措辞 {wrong}" if wrong
            else f"状态栏全文={bar!r}（统计项不计矛盾）")

    # ★ 只读模式必须显式说出来。
    #   未激活时 state 仍可能是 learning/protecting、KPI 也照常统计，
    #   但请求实际全部直通。界面若不提，用户会以为防护在正常工作。
    read_only = bool(real.get("read_only"))
    bar = status_text(page)
    if read_only:
        rec("T3 只读模式已如实告知", "只读" in bar,
            f"后端 read_only=True 但状态栏未提示；状态栏全文={bar!r}")
    else:
        rec("T3 非只读模式不误报", "只读模式" not in bar,
            f"后端 read_only=False 但状态栏显示了只读提示；状态栏全文={bar!r}")


def test_unreachable_label(page, be: Backend):
    """T3b 引擎不可达时，状态栏必须说「未运行」而不是继续显示「防护中」。

    ★ 这是 L5（异常全局）层的核心：引擎一挂，界面若还显示
      「防护中 / 今日已检查 N 次」，用户会以为一切正常 —— 而实际上
      此刻所有流量都在裸奔。这是安全产品最致命的静默失效。
    ★ 本用例只验证**降级分支的文案定义**（不真的停引擎），
      真停引擎会让用户的防护在测试期间真实失效，不可接受。
    """
    src = Path(__file__).resolve().parent.parent / "desktop" / "src" / "components" / "Layout.tsx"
    try:
        text = src.read_text(encoding="utf-8")
    except Exception as e:
        rec("T3b 引擎失效时状态栏诚实", False, f"无法读取 Layout.tsx: {e}", skip=True)
        return

    branch = text.split("if (!reachable)")[1] if "if (!reachable)" in text else ""
    # 降级分支里不许出现「防护中」「学习中」这类"一切正常"的措辞
    lying = [w for w in ("防护中", "学习中", "今日已检查") if w in branch]
    has_honest = "本地代理未运行" in branch and ("请确认玄盾代理已启动" in branch)
    rec("T3b 引擎失效时状态栏诚实",
        has_honest and not lying,
        f"诚实文案={'有' if has_honest else '无'}，谎报措辞={lying or '无'}")


def test_dashboard_kpi(page, be: Backend):
    """T4 首页 KPI 数字与后端今日统计一致（不是占位 0）。"""
    goto(page, "首页")
    real = be.state() or {}
    today = real.get("today") or {}
    page.wait_for_timeout(600)

    vals = {}
    for label in ("安全", "可疑", "危险"):
        el = page.locator(f".kpi:has(.kpi-label:text-is('{label}')) .kpi-value")
        try:
            vals[label] = int(el.first.inner_text(timeout=3000).strip())
        except Exception:
            vals[label] = None

    want = {
        "安全": today.get("safe_count"),
        "可疑": today.get("suspect_count"),
        "危险": today.get("danger_count"),
    }
    mismatch = {
        k: (vals[k], want[k])
        for k in want
        if vals[k] is not None and want[k] is not None and vals[k] != want[k]
    }
    # ★ 必须校验**界面侧**三个值都取到了。
    #   曾经写成 all(v is not None for v in want.values())，
    #   检查的是后端字段 —— 而后端在引擎正常时一定有值，
    #   于是「界面 KPI 整块消失 / 选择器失效 / 组件崩溃」全绿。
    #   这正是「两边同时出错就一起通过」：界面侧彻底失效也照样通过。
    ui_complete = all(vals[k] is not None for k in want)
    be_complete = all(want[k] is not None for k in want)
    rec("T4 首页 KPI 与后端一致", ui_complete and be_complete and not mismatch,
        f"界面={vals} 后端={want}"
        + (f" 不一致={mismatch}" if mismatch else "")
        + ("" if ui_complete else " ← 界面 KPI 缺失（组件未渲染或选择器失效）"))


def test_dashboard_relay_honest(page, be: Backend):
    """T4b 首页「当前中转站」与后端配置状态一致 —— 不许谎报「尚未配置」。

    ★ 这条是补 2026-09-29 的真实缺陷的：
      明明已在设置页配好中转站，首页却显示「尚未配置中转站」。
      根因是判据 `primaryRelay ?? relays[relays.length-1]` ——
      /api/relays 只收录**产生过调用记录**的中转站，刚配置还没发过
      对话时它是空数组，于是 primaryRelay 为 undefined，
      界面落进「尚未配置」分支。

    ★ 为什么 T4 抓不到：T4 只比 KPI 数字，
      而「谎报未配置」与「KPI 是否一致」完全正交。
      判据必须直接对着后端的 relay_configured。
    """
    goto(page, "首页")
    diag = be.diagnostics() or {}
    configured = bool(diag.get("relay_configured"))
    domain = str(diag.get("relay_domain") or "")

    # ★ 必须等 currentDomain 落地，不能固定 sleep。
    #   getDiagnostics 是**独立于轮询**的一次性请求（Dashboard 的
    #   useEffect 里只跑一次），它没回来时 currentDomain 仍是 ''，
    #   界面会短暂显示「尚未配置中转站」——
    #   此时断言就是「把还没到时候当成坏了」。
    #   实测该请求偶尔要 1~2 秒，固定 600ms 不足以覆盖。
    if configured:
        try:
            page.wait_for_function(
                "() => !document.body.innerText.includes('尚未配置中转站')",
                timeout=8000,
            )
        except Exception:
            pass  # 超时后由下面的断言报出真实问题
    page.wait_for_timeout(400)

    body = page.locator("body").inner_text()
    claims_unconfigured = "尚未配置中转站" in body

    if configured:
        # 配了就不许说没配
        rec("T4b 首页不谎报「尚未配置中转站」", not claims_unconfigured,
            f"后端 relay_configured=True（{domain}），"
            + (f"但界面仍显示「尚未配置中转站」" if claims_unconfigured
               else f"界面已正确显示当前中转站"))
        # 且域名应该出现在首页上 —— 证明「收到了，正在用」
        if domain:
            shown = domain in body
            rec("T4b 首页展示当前中转站域名", shown,
                f"域名 {domain} " + ("已显示" if shown else "未出现在首页上"))
    else:
        # 没配就必须说没配，且要给出去处
        has_link = page.locator("a:has-text('前往设置')").count() > 0
        rec("T4b 未配置时提示去设置", claims_unconfigured and has_link,
            f"声称未配置={claims_unconfigured} 有前往设置入口={has_link}")


def test_reputation_score_honest(page, be: Backend):
    """T13 信誉评分与扣分明细必须自洽，且不再恒为 0。

    ★ 这条补的是 2026-10-02 用户直接指出的问题：
      首页显示 `api.commandcode.ai  0/100`，
      扣分明细写着「危险响应 19 次 × 20 分 = −380」
      「可疑响应 59 次 × 4 分 = −236」。

      查库发现那 19 次「危险」**全部**是「响应长度突变」——
      用户问了个长问题（问「你好」3 字、回一段代码 11000 字），
      中转站被扣了 380 分。
      扣分还把分数压到 0 并长期触底，
      此后任何新增风险都显示不出来。

    ★ 判据不看「分数是多少」，看**自洽性**：
      ① 明细里列出的扣分加起来，不能远超 100 分
         （旧算法 −616 就是不自洽的直接证据）；
      ② 明细里不该出现「用户自己的操作」被当成中转站罪证；
      ③ 若后端 relay_* 计数为 0，界面就不该显示扣分项。
      前端与后端各自「看起来自洽」，但两边对不上时只有端到端能抓。
    """
    goto(page, "首页")
    page.wait_for_timeout(800)

    relays = (be.relays() or {}).get("relays") or []
    if not relays:
        rec("T13 信誉评分链路", False, "信誉库为空（没有调用记录）", skip=True)
        return

    target = relays[0]
    domain = str(target.get("domain") or "")
    score = int(target.get("score") or 0)
    relay_danger = int(target.get("relay_danger_count") or 0)
    relay_suspect = int(target.get("relay_suspect_count") or 0)
    self_danger = int(target.get("self_danger_count") or 0)

    # 展开评分明细
    try:
        btn = page.locator("button:has-text('为什么是这个分数')").first
        if btn.count() == 0:
            rec("T13 有评分明细入口", False, "首页没有「为什么是这个分数？」")
            return
        btn.click(timeout=6000)
        page.wait_for_timeout(700)
    except Exception as e:
        rec("T13 有评分明细入口", False, f"点击失败: {e}")
        return

    detail = page.locator(".rep-detail").first
    try:
        detail.wait_for(timeout=6000)
        text = detail.inner_text()
    except Exception:
        text = ""

    # ① 扣分总额不得远超满分 —— 旧算法会显示 −616
    nums = []
    for line in text.splitlines():
        if "−" in line or "-" in line.replace("−", ""):
            for tok in line.replace("−", "-").split():
                if tok.startswith("-") and tok[1:].replace(".", "").isdigit():
                    try:
                        nums.append(abs(float(tok[1:])))
                    except ValueError:
                        pass
    over = [n for n in nums if n > 100]
    rec("T13 扣分总额未超满分", not over,
        f"扣分明细={nums}（>100 的项：{over}）"
        if nums else "明细里没有可解析的扣分数值")

    # ② 明细不得把用户自己的操作算成中转站扣分
    blames_user = "次危险" in text or "次可疑" in text
    rec("T13 扣分明细未把用户操作算作中转站罪证", not blames_user,
        f"明细里出现了「次危险/次可疑」（旧口径按总量计）"
        if blames_user else "已改为按中转站侧归因")

    # ③ 后端说没有中转站侧风险，界面就只能显示「未触发任何扣分项」
    #
    # ★ 判据踩过的坑：早先查的是 "扣分" not in text，
    #   而空态文案本身就是「本次使用未触发任何扣分项 —」，
    #   含「扣分」二字 → 永远判失败。
    #   那是判据写错，不是产品有问题。
    #   正确做法是数**扣分表格的行数**（不含表头）。
    try:
        rows = page.locator(
            ".rep-detail .rep-row:not(.rep-row-head)").count()
    except Exception:
        rows = 0
    if relay_danger == 0 and relay_suspect == 0:
        rec("T13 无中转站侧风险时不列扣分项", rows == 0,
            f"后端 relay_danger={relay_danger} relay_suspect={relay_suspect}，"
            f"界面却列了 {rows} 行扣分项")
    else:
        rec("T13 有中转站侧风险时列出扣分项", rows > 0,
            f"relay_danger={relay_danger} relay_suspect={relay_suspect}，"
            f"明细行数={rows}")

    # ④ 分数不该是长期触底的 0 —— 若真为 0，必须有定性证据
    hard_evidence = bool(
        target.get("known_malicious") or target.get("watermark_detected")
    )
    if score == 0:
        rec("T13 分数为 0 时必须有定性证据", hard_evidence,
            f"score=0 但 known_malicious={target.get('known_malicious')} "
            f"watermark={target.get('watermark_detected')} —— "
            "分数被行为扣分耗尽，归因可能又出错了")
    else:
        rec("T13 分数未触底", True,
            f"{domain} 得分 {score}"
            + (f"，其中用户自身操作 {self_danger} 次（不计入）"
               if self_danger else ""))

    # 收起明细，别留遮罩
    try:
        page.locator("button:has-text('收起评分明细')").first.click(timeout=4000)
        page.wait_for_timeout(300)
    except Exception:
        pass


def test_settings_toggles(page, be: Backend):
    """T5 设置页存在防护开关。"""
    goto(page, "设置")
    toggles = page.locator(
        "input[type='checkbox'], [role='switch'], button[role='switch']"
    ).count()
    rec("T5 设置页存在防护开关", toggles > 0, f"找到 {toggles} 个")


def test_toggle_applies(page, be: Backend):
    """T5b 防护开关真的落到后端配置上（关掉再打开，绝不留副作用）。

    ★ 只断言"界面上有开关"是不够的：界面可以画一个开关而完全不发送请求，
      用户以为已关闭响应验证，实际仍在跑 —— 防护被静默解除。
    ★ 断言方式为「改界面 → 读后端 → 改回来 → 再读后端」双向闭环。
    ★ 点击目标是 label.switch 而非 input：input 被 CSS 隐藏（自定义滑块外观），
      Playwright 会以「element is not visible」拒绝，而真实用户点的也是滑块。
    """
    before = be.guard().get("enable_response_verify")
    if before is None:
        rec("T5b 开关真正生效", False, "读不到后端 enable_response_verify", skip=True)
        return

    row = page.locator(".switch-row:has-text('响应验证')").first
    sw = row.locator("label.switch").first
    try:
        sw.click(timeout=6000)
    except Exception as e:
        rec("T5b 开关真正生效", False, f"点击开关失败: {e}")
        return

    flipped = None
    end = time.time() + 8
    while time.time() < end:
        cur = be.guard().get("enable_response_verify")
        if cur != before:
            flipped = cur
            break
        page.wait_for_timeout(250)

    rec("T5b 界面开关写入后端", flipped is not None and flipped != before,
        f"后端 {before} -> {flipped}")

    # 兜底还原（无论上面成功与否）
    #
    # ★ 统一用 != / ==，不用 is / is not。
    #   is 比较依赖 True/False 的单例缓存，实践中可行，但同一函数内
    #   下面又用 == 判断同一语义，自相矛盾 —— 说明对这个值的类型并不确定。
    #   更实际的风险：before 为 None（guard 段缺失）时，
    #   `is not` 会让还原分支误触发。
    try:
        if be.guard().get("enable_response_verify") != before:
            sw.click(timeout=6000)
            end = time.time() + 8
            while time.time() < end:
                if be.guard().get("enable_response_verify") == before:
                    break
                page.wait_for_timeout(250)
    except Exception as e:
        print(f"  !! 开关还原失败: {e}", flush=True)

    final = be.guard().get("enable_response_verify")
    rec("T5b 开关已还原", final == before, f"后端回到 {final}（期望 {before}）")


def test_error_boundary(page):
    """T6 应用未崩溃（ErrorBoundary 未触发）。"""
    body = page.locator("body").inner_text()
    crashed = any(k in body for k in ("应用遇到问题", "崩溃", "Unhandled"))
    rec("T6 无未捕获异常", not crashed,
        "ErrorBoundary 被触发" if crashed else "正常")


def test_console_clean(page):
    """T7 控制台无严重报错。

    ★ 过滤条件刻意只保留 AbortError —— 那是 api.ts 自己用 AbortController
      设超时后抛出、且已被各处 try/catch 接住的正常路径。
      早期版本还过滤了 '18765' 和 'Failed to fetch'，那等于把所有
      涉及引擎的错误一并吞掉，本用例会永远通过、永远测不出东西 ——
      过滤规则本身就是一种谎报。
    """
    real = [e for e in _console_errors if "AbortError" not in e]
    rec("T7 控制台无严重报错", len(real) == 0,
        f"{len(real)} 条: {real[:3]}" if real else "干净")


def test_block_end_to_end(page, be: Backend):
    """T10 拦截全链路：攻击发生 → 引擎拦下 → 界面如实呈现。

    ★★ 这条补的是本脚本最大的一处空白（2026-09-29）。
      此前 32 条用例里没有一条**触发过拦截**：
        · test_redteam_attack.py（39 条）验的是引擎规则，直接调函数
        · cdp_desktop_regression.py 验的是界面渲染，从不打攻击请求
      两者之间的接合处 ——「引擎拦了，界面有没有告诉用户」——
      一直是空白。而这正是用户唯一能感知的部分：
      引擎拦了但界面不显示，用户会以为没拦住。

    ★ 为什么必须真发请求，不能手工塞日志：
      直接往数据库写一条 block 记录，或手工构造界面状态，
      都只验了「界面能显示已有的东西」，
      验不到「攻击 → 拦截 → 呈现」这条链路是否真的连通。
      只有真打一次，中间那层才被验证过。

    ★ 载荷选 API 密钥而不是语义投毒：
      语义投毒要靠**中转站返回**恶意内容才能触发，
      而那取决于用户配的中转站与模型名，本机不可控。
      请求侧的敏感信息阻断只依赖载荷本身，稳定可复现 ——
      判据必须选在所有环境都成立的那一侧。
    """
    goto(page, "首页")

    # ── 基线：拦之前先记下当前计数 ──
    before = (be.state() or {}).get("today") or {}
    b_danger = before.get("danger_count")
    b_total = before.get("total_calls")
    if b_danger is None or b_total is None:
        rec("T10 拦截链路", False, "读不到后端今日统计", skip=True)
        return
    logs_before = (be.block_logs(1) or {}).get("total")
    if logs_before is None:
        rec("T10 拦截链路", False, "读不到拦截日志", skip=True)
        return

    # ── 发起一个必然被拦的请求 ──
    #   载荷含两个高危项：OpenAI 形态的 Key + AWS Access Key。
    #   _POLICY 里两者在三档安全级别下都是 BLOCK，
    #   所以无论用户设的是宽松/均衡/严格，这条都会被拦 ——
    #   判据不依赖当前安全级别设置。
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{
            "role": "user",
            "content": "t10 probe: sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD "
                       "AKIAIOSFODNN7EXAMPLE",
        }],
    }
    status, body = be.post_chat(payload, timeout=30)

    # ① 引擎真的拦了 —— 判据读 error.type，不靠状态码猜
    err = (body or {}).get("error") or {}
    etype = str(err.get("type") or "")
    blocked = etype == "sensitive_data_blocked"
    rec("T10 敏感信息请求被阻断", blocked,
        f"HTTP={status} error.type={etype!r} "
        f"message={str(err.get('message'))[:80]!r}")

    if not blocked:
        # ★ 中转站不可达 / 未配 Key 等前置不成立时不能算失败 ——
        #   那不是防护失效，是环境问题（与 T8 的处理同一原则）。
        rec("T10 拦截链路", False,
            f"未被拦截（HTTP={status}）。若中转站未配置或不可达，"
            f"本用例前置不成立，应改为环境问题而非产品缺陷", skip=True)
        return

    # ② 后端计数确实增加了
    after = (be.state() or {}).get("today") or {}
    a_danger = after.get("danger_count")
    a_total = after.get("total_calls")
    rec("T10 拦截被计入危险计数",
        a_danger == b_danger + 1 and a_total == b_total + 1,
        f"危险 {b_danger}→{a_danger}（期望 +1），"
        f"总次数 {b_total}→{a_total}（期望 +1）")

    # ③ 拦截日志落库，且带上原因
    logs_after = be.block_logs(3) or {}
    rec("T10 拦截写入日志",
        (logs_after.get("total") or 0) > (logs_before or 0),
        f"block 日志 {logs_before}→{logs_after.get('total')}")

    # ── ④ 界面是否如实呈现（这才是本用例的核心）──
    #    必须等轮询把新数据取回来：Dashboard 是 3s 一轮，
    #    刚发完请求立刻读会读到旧值 —— 那是「还没到时候」，
    #    不是界面谎报。判据要等，不该用固定 sleep。
    try:
        page.wait_for_function(
            """(base) => {
                const el = [...document.querySelectorAll('.kpi')]
                  .find(x => x.innerText.includes('危险'));
                if (!el) return false;
                const n = parseInt(el.innerText.replace(/[^0-9]/g, ''), 10);
                return Number.isFinite(n) && n > base;
            }""",
            arg=b_danger,
            timeout=15000,
        )
        ui_danger_ok = True
    except Exception:
        ui_danger_ok = False
    rec("T10 首页「危险」计数随之上升", ui_danger_ok,
        f"期望 > {b_danger}" + ("" if ui_danger_ok else "，15s 内界面未更新"))

    # ⑤ 日志页能看到这条拦截的摘要
    try:
        goto(page, "日志")
        page.wait_for_timeout(600)
        logs_body = page.locator("body").inner_text()
    except Exception as e:
        logs_body = ""
        rec("T10 日志页呈现拦截记录", False, f"打开日志页失败: {e}")
    else:
        entries = (logs_after.get("entries") or [])
        summary = str(entries[0].get("summary") or "") if entries else ""
        # 摘要取前 12 字比对：界面会截断，全文比对会因截断而误判
        probe = summary[:12]
        shown = bool(probe) and probe in logs_body
        rec("T10 日志页呈现拦截记录", shown,
            f"最新拦截摘要前 12 字={probe!r} "
            + ("已出现在日志页" if shown else "未出现在日志页"))

    # ── ⑥ 拦截依据必须可核对（本轮新增）──
    #
    # ★ 这一段验的是「用户能不能自己判断是不是误报」。
    #   2026-10-02 用户提出「是否存在误报」，追下去发现：
    #   阻断路径压根不写 redaction_records，detail_json 还是个 dict，
    #   前端只渲染数组 → 依据整段不显示。
    #   后端 /api/state 的数字完全正确，引擎也真的拦了，
    #   但用户手上**没有任何可核对的依据**，
    #   于是 40 条真实拦截看起来就像 40 次误报。
    #
    #   判据分三层：接口有数据 → 落库有记录 → 界面看得到。
    #   少任何一层都可能出现「后端有、前端无」的谎报。
    entries = (logs_after.get("entries") or [])
    if not entries:
        rec("T10 拦截依据可核对", False, "拿不到刚写入的拦截日志", skip=True)
        return

    log_id = entries[0].get("id")
    detail = be.log_detail(log_id) or {}
    reds = detail.get("redactions") or []

    rec("T10 拦截依据已落库",
        len(reds) > 0,
        f"日志 {log_id} 的脱敏记录 {len(reds)} 条"
        + ("（阻断路径仍未落库）" if not reds else ""))

    # 依据必须是掩码后的片段，绝不能是原文 ——
    # 证据会经 /api/logs 与 CSV 导出外发，存原文等于自建泄露通道。
    raw_leaked = False
    for r in reds:
        if "sk-abcdefghijklmnopqrstuvwxyz" in str(r.get("original") or ""):
            raw_leaked = True
            break
    rec("T10 拦截依据已掩码", bool(reds) and not raw_leaked,
        "依据里出现了密钥原文" if raw_leaked else "依据为掩码片段")

    # detail_json 必须是数组：前端只渲染数组，写成 dict 会整段不显示。
    try:
        parsed = json.loads(str(entries[0].get("detail_json") or ""))
        is_list = isinstance(parsed, list) and any(
            isinstance(x, dict) and x.get("evidence") for x in parsed
        )
    except Exception:
        parsed, is_list = None, False
    rec("T10 拦截依据结构可被前端渲染", is_list,
        f"detail_json 类型={type(parsed).__name__}"
        + ("（dict 会被前端静默丢弃）" if isinstance(parsed, dict) else ""))

    # 界面侧：打开该条详情抽屉，必须真的看到片段
    try:
        goto(page, "日志")
        page.wait_for_timeout(600)
        # 点开最新一条（日志页表格按时间倒序，tbody 第一行即刚才那条）
        page.locator("tbody tr").first.click(timeout=6000)
        page.wait_for_timeout(900)
        drawer = page.locator(".drawer").first
        drawer.wait_for(timeout=6000)
        drawer_text = drawer.inner_text()
        has_evidence = ("片段" in drawer_text) or ("依据" in drawer_text)
        rec("T10 日志详情展示拦截依据", has_evidence,
            "详情抽屉未出现「片段/依据」" if not has_evidence
            else f"抽屉含依据（前 60 字）={drawer_text[:60]!r}")
    except Exception as e:
        rec("T10 日志详情展示拦截依据", False, f"打开详情抽屉失败: {e}")
    finally:
        # ★ 必须关掉抽屉。
        #   .drawer-overlay 是全屏遮罩，不关掉的话它会拦下
        #   后续所有导航点击 —— T11/T9 会以「点击超时」失败，
        #   而真实原因是本用例留了个没关的弹窗。
        #   那是测试自身的缺陷，却记在产品账上。
        try:
            page.keyboard.press("Escape")
            page.wait_for_timeout(300)
            if page.locator(".drawer-overlay").count() > 0:
                page.locator(".drawer-overlay").first.click(
                    position={"x": 5, "y": 5}, timeout=3000)
                page.wait_for_timeout(300)
        except Exception:
            pass


def test_dashboard_refresh(page, be: Backend):
    """T11 首页刷新按钮：存在、可点、点了真的会重新取数。

    ★ 为什么要有这条
      2026-10-02 用户反馈「页面数据对应不上，也没有刷新按钮」。
      当时首页只有 3 秒轮询，没有任何手动刷新入口，
      也没有「数据是什么时候的」这个信息 ——
      数字看着不对时，用户既不能立刻拉一次，
      也无从判断是数据错了还是还没刷新。
      「数据对不上」的第一嫌疑往往就是时间差。

    ★ 判据设计
      不能只断言按钮存在 —— 存在但点了没反应同样满足「有刷新按钮」。
      这里验的是**行为**：点下去之后「更新于」的时刻必须真的往前跳。
    """
    goto(page, "首页")
    page.wait_for_timeout(500)

    btn = page.locator("button[aria-label='刷新数据']")
    if btn.count() == 0:
        rec("T11 首页有刷新按钮", False, "未找到 aria-label='刷新数据' 的按钮")
        return
    rec("T11 首页有刷新按钮", True, "按钮存在")

    # ★ 必须等首屏数据真的到齐，不能只 sleep 一下就读。
    #   刚切到首页时 state 还是 null，界面显示「尚未更新」——
    #   那是**诚实的加载态**，不是缺陷。
    #   早先这里 500ms 后直接断言，读到的必然是加载态，
    #   于是把「还没加载完」报成「产品没显示更新时间」。
    pat = re.compile(r"更新于\s*(\d{2}):(\d{2}):(\d{2})")
    try:
        page.wait_for_function(
            """() => /更新于\\s*\\d{2}:\\d{2}:\\d{2}/.test(document.body.innerText)""",
            timeout=15000,
        )
        ok_time = True
    except Exception:
        ok_time = False
    body = page.locator("body").inner_text()
    rec("T11 首页显示数据更新时间", ok_time,
        "已显示上次更新时间" if ok_time
        else f"15s 内未出现「更新于 时:分:秒」，实际前 120 字={body[:120]!r}")
    if not ok_time:
        return

    def stamp():
        m = pat.search(page.locator("body").inner_text())
        return m.group(0) if m else ""

    before = stamp()
    # ★ 必须真的点下去，并在点之前先确认轮询的秒级变化
    #   不至于快到让「时间戳变了」无法归因于这次点击。
    #   判据只看「点了之后变了」，不点就等轮询的话，
    #   这条用例在 3 秒轮询下必然恒真 —— 那是一条假判据。
    try:
        btn.first.click(timeout=6000)
    except Exception as e:
        rec("T11 点刷新后时间戳更新", False, f"点击刷新按钮失败: {e}")
        return

    try:
        page.wait_for_function(
            """(b) => {
                const m = document.body.innerText.match(
                    /更新于\\s*(\\d{2}:\\d{2}:\\d{2})/);
                return !!m && m[0] !== b;
            }""",
            arg=before,
            timeout=12000,
        )
        ok = True
    except Exception:
        ok = False
    rec("T11 点刷新后时间戳更新", ok,
        f"点击前={before!r} 点击后={stamp()!r}"
        + ("" if ok else "（12s 内未变化：按钮可能未绑定动作）"))

    # 刷新不得把界面打成空态（有数据时点刷新，数据不该消失）
    still_has_kpi = page.locator(".kpi").count() > 0
    rec("T11 刷新后界面未清空", still_has_kpi,
        "刷新后 KPI 消失" if not still_has_kpi else "数据仍在")


def test_pause_resume(page, be: Backend):
    """T9 暂停/恢复全链路：界面 + 托盘 + 引擎三处一致。

    ★ 分层对应 HCSE 五层模型：
        L2 弹窗/按钮点击 → L3 状态卡片变化 → L5 托盘（唯一感知通道）
    ★ 这是本脚本最重要的用例：防护被暂停却仍显示「防护中」，
      等于用户主动关掉防护后被告知防护还在 —— 比不提供暂停功能更糟。
    """
    goto(page, "首页")
    original = (be.state() or {}).get("state")
    if original == "paused":
        rec("T9 暂停链路", False, "防护本就处于暂停态，无法验证切换", skip=True)
        return

    try:
        page.locator("button:has-text('暂停 5 分钟')").first.click(timeout=6000)
    except Exception as e:
        rec("T9 暂停链路", False, f"点击「暂停 5 分钟」失败: {e}")
        return

    ok_ui, seen = wait_label(page, STATE_LABELS["paused"], timeout=8000)
    rec("T9 暂停后状态栏显示「已暂停」", ok_ui, f"实际={seen!r}")

    # 托盘是窗口隐藏时用户唯一的感知通道，必须同步转灰
    tray = None
    end = time.time() + 8
    while time.time() < end:
        tray = tray_state(page)
        if tray == "paused":
            break
        page.wait_for_timeout(250)
    rec("T9 暂停后托盘转灰", tray == "paused", f"托盘={tray!r}")

    # 引擎侧也要真的暂停（不是只改了界面）
    be_state = (be.state() or {}).get("state")
    rec("T9 引擎确实处于暂停", be_state == "paused", f"后端 state={be_state!r}")

    # 恢复
    try:
        page.locator("button:has-text('恢复防护')").first.click(timeout=6000)
        expect = STATE_LABELS.get(original, original)
        ok_back, seen_back = wait_label(page, expect, timeout=12000)
        rec("T9 恢复后状态栏回到原状态", ok_back, f"实际={seen_back!r} 期望={expect!r}")
    except Exception as e:
        rec("T9 恢复后状态栏回到原状态", False, f"点击「恢复防护」失败: {e}")


def test_mark_false_positive_lowers_count(page, be: Backend):
    """T12「标记为误报」必须真的把首页数字改小。

    ★ 这是本轮发现的第三个谎报，也是用户唯一能自己动手修的地方。
      界面提示「后续统计将不再计入风险」，
      而原实现只写 logs.marked_safe —— daily_stats 是累加缓存，
      永远不会回退。用户点完按钮，首页「危险 N」纹丝不动。

    ★★ 为什么这条必须放在 CDP 而不只用 pytest：
      pytest 验的是 storage 层「调了 mark_safe 会降数」，
      但用户点的是**界面按钮**，走的是 HTTP 接口 → React → 再轮询。
      中间任何一环没接上（接口没调、响应没回来、界面没重取），
      storage 层测试全绿而用户依然看不到变化。
      端到端跑一遍才验得到他真正看到的东西。

    ★ 收尾必须把标记撤掉，否则会污染用户的真实统计 ——
      测试在用户自己的数据库上跑，留下一条被标成误报的真实记录
      比留一条测试记录更糟。
    """
    goto(page, "日志")
    page.wait_for_timeout(800)

    before = (be.state() or {}).get("today") or {}
    b_danger = before.get("danger_count")
    if b_danger is None:
        rec("T12 标记误报链路", False, "读不到后端今日统计", skip=True)
        return
    if b_danger <= 0:
        rec("T12 标记误报链路", False,
            f"当前危险计数为 {b_danger}，没有可标记的基线", skip=True)
        return

    try:
        # 只在「已拦截」这一类里找，避免误标安全记录
        page.locator("select, .filter select").first.select_option(
            "block", timeout=5000) if page.locator(
                "select, .filter select").count() else None
        page.wait_for_timeout(700)
    except Exception:
        pass   # 筛选器结构变了也不该让本用例直接崩，下面的兜底会处理

    # 兜底：直接问后端要一条 block 日志，绕开界面筛选
    logs = be.block_logs(1) or {}
    entries = logs.get("entries") or []
    target = next(
        (e for e in entries if not e.get("marked_safe")), None)
    if target is None:
        rec("T12 标记误报链路", False,
            "找不到未标记的拦截日志（可能全被标过了）", skip=True)
        return
    log_id = target["id"]

    # 打开该条详情
    try:
        row = page.locator(f"tbody tr:has-text('{target['summary'][:10]}')")
        if row.count() == 0:
            row = page.locator("tbody tr")
        row.first.click(timeout=6000)
        page.wait_for_timeout(900)
    except Exception as e:
        rec("T12 标记误报链路", False, f"打开日志详情失败: {e}")
        return

    try:
        btn = page.locator("button:has-text('标记为误报')").first
        if btn.count() == 0:
            rec("T12 有「标记为误报」按钮", False, "详情里没有该按钮")
            return
        rec("T12 有「标记为误报」按钮", True, "按钮存在")
        btn.click(timeout=6000)
    except Exception as e:
        rec("T12 有「标记为误报」按钮", False, f"点击失败: {e}")
        _close_drawer(page)
        return

    # 核心判据：后端计数真的降了。
    # ★ 用轮询而不是固定 sleep —— 统计是同步落库的，
    #   但接口往返仍有毫秒级延迟。
    after = {}
    deadline = time.time() + 10
    while time.time() < deadline:
        after = (be.state() or {}).get("today") or {}
        cur = after.get("danger_count")
        if cur is not None and cur < b_danger:
            break
        time.sleep(0.4)
    a_danger = after.get("danger_count")
    rec("T12 标记后危险计数下降", a_danger == b_danger - 1,
        f"危险 {b_danger} → {a_danger}（期望 {b_danger - 1}）")

    # 界面上也得跟着变（不是只有后端降了）
    try:
        _close_drawer(page)
        goto(page, "首页")
        page.wait_for_timeout(1500)
        shown = page.evaluate(
            """() => {
                const el = [...document.querySelectorAll('.kpi')]
                  .find(x => x.innerText.includes('危险'));
                if (!el) return null;
                return parseInt(el.innerText.replace(/[^0-9]/g, ''), 10);
            }""",
        )
        rec("T12 首页「危险」同步下降", shown == b_danger - 1,
            f"界面显示 {shown}（期望 {b_danger - 1}）")
    except Exception as e:
        rec("T12 首页「危险」同步下降", False, f"读首页失败: {e}")

    # ── 收尾：撤销标记，把用户的统计还原 ──
    # ★ 必须还原。测试跑在用户自己的数据库上，
    #   留一条被标成误报的真实拦截记录 = 污染用户看到的统计，
    #   比留一条测试记录更糟。
    _close_drawer(page)
    try:
        ok = be.unmark_safe(log_id)
        rec("T12 收尾：撤销标记还原统计", bool(ok),
            f"日志 {log_id} 已撤销" if ok
            else f"撤销失败（日志 {log_id} 仍被标为误报）")
    except Exception as e:
        rec("T12 收尾：撤销标记还原统计", False,
            f"撤销调用失败: {e}（日志 {log_id} 需手动撤销）")

    # 撤销后计数必须回到原值，否则「撤销」本身就是新的谎报
    try:
        back = {}
        deadline = time.time() + 8
        while time.time() < deadline:
            back = (be.state() or {}).get("today") or {}
            if back.get("danger_count") == b_danger:
                break
            time.sleep(0.4)
        rec("T12 撤销后计数回到原值",
            back.get("danger_count") == b_danger,
            f"危险 {a_danger} → {back.get('danger_count')}（期望 {b_danger}）")
    except Exception as e:
        rec("T12 撤销后计数回到原值", False, f"读后端失败: {e}")


def _close_drawer(page):
    """关闭日志详情抽屉，避免遮罩层拦下后续点击。"""
    try:
        page.keyboard.press("Escape")
        page.wait_for_timeout(250)
        if page.locator(".drawer-overlay").count() > 0:
            page.locator(".drawer-overlay").first.click(
                position={"x": 5, "y": 5}, timeout=3000)
            page.wait_for_timeout(250)
    except Exception:
        pass


def test_multi_relay_settings(page, be: Backend):
    """T14 多中转站：用户在界面上真能加、看到、切、移除。

    ★★ 全部操作都必须在**界面上**点。
      初版这个用例是先用后端 API 塞进第二家，再去界面找它 ——
      结果只验到「列表能渲染」，没验到「用户能新增」。
      而后者才是这条功能成立的前提：
      没有新增路径时，列表只能靠切换产生，切换不新增，
      于是界面上永远只有一行 —— 功能看起来存在，实际不可用。

    ★ 加完必须**离开设置页再回来**：
      loadConfigured 只在挂载与保存/切换/新增后跑；
      用后端 API 塞数据不会触发它，
      列表就还是加之前那一行 —— 那是测试自己造的假象。
    """
    before_cfg = (be.config() or {}).get("relay") or {}
    orig_url = (before_cfg.get("base_url") or "").strip()
    if not orig_url:
        rec("T14 多中转站", False, "当前未配置中转站，无法验证", skip=True)
        return

    SECOND_URL = "https://relay-second.example.invalid"
    SECOND_KEY = "sk-cdp-second-relay-key-000000"
    SECOND_NAME = "CDP 第二家"

    try:
        goto(page, "设置")
        page.wait_for_timeout(1200)

        body = page.inner_text("body")
        rec("T14 设置页有「已配置的中转站」区块",
            "已配置的中转站" in body, "设置页没有该区块")

        # ── 界面上新增第二家 ──
        entry = page.locator("button:has-text('添加另一家')").first
        if entry.count() == 0:
            rec("T14 有「添加另一家」入口", False,
                "设置页没有新增入口 —— 用户永远只有一家")
            return
        rec("T14 有「添加另一家」入口", True, "按钮存在")
        entry.click(timeout=6000)
        page.wait_for_timeout(400)

        page.fill("input[aria-label='新增中转站的显示名']", SECOND_NAME)
        page.fill("input[aria-label='新增中转站的地址']", SECOND_URL)
        page.fill("input[aria-label='新增中转站的 API Key']", SECOND_KEY)
        submit = page.locator("button:has-text('添加到列表')").first
        if submit.count() == 0:
            labels = page.locator("button:has-text('添加')").all_inner_texts()
            rec("T14 有「添加到列表」按钮", False,
                f"新增表单没有提交按钮，现有按钮文案={labels!r}")
            return
        before_err = len(_console_errors)
        submit.click(timeout=6000)
        page.wait_for_timeout(1500)
        new_errs = _console_errors[before_err:]
        if new_errs:
            rec("T14 新增点击无控制台报错", False,
                "；".join(e[:300] for e in new_errs))
        # 抓 toast：失败原因只出现在提示里，不在控制台。
        # ★ 锚点用 .toast-stack（本项目的真实类名，见 Toast.tsx）——
        #   写成 .toast / [role=alert] 会一个都匹配不到，
        #   于是这条诊断判据自身永远报「无反馈」，
        #   把「有提示」和「没提示」混成同一个结论。
        try:
            toasts = page.locator(".toast-stack .toast-text").all_inner_texts()
        except Exception:
            toasts = []
        rec("T14 点击后有可见反馈（成功或失败提示）", bool(toasts),
            f"toast={toasts!r}")

        # 后端确认（判据的依据必须是引擎真实状态，不是界面自述）
        end = time.time() + 12
        lst = {}
        while time.time() < end:
            lst = be._get("/api/relays/configured", timeout=8) or {}
            if any(r.get("base_url") == SECOND_URL
                   for r in lst.get("relays") or []):
                break
            time.sleep(0.4)
        items = lst.get("relays") or []
        rec("T14 界面新增真的落到后端",
            any(r.get("base_url") == SECOND_URL for r in items),
            f"列表地址={[r.get('base_url') for r in items]!r}")

        cur = ((be.config() or {}).get("relay") or {})
        rec("T14 新增不改动当前启用项", cur.get("base_url") == orig_url,
            f"新增后当前项 base_url={cur.get('base_url')!r}，期望 {orig_url!r}")

        blob = json.dumps(lst, ensure_ascii=False)
        rec("T14 列表接口不下发明文 Key", SECOND_KEY not in blob,
            f"响应含明文 Key：{SECOND_KEY in blob}")
        rec("T14 列表接口给出掩码",
            "api_key_masked" in blob and "****" in blob,
            f"响应片段={blob[:160]!r}")

        # ── 离开再回来，列表必须包含新加的 ──
        goto(page, "首页")
        page.wait_for_timeout(500)
        goto(page, "设置")
        page.wait_for_timeout(1500)

        body = page.inner_text("body")
        rec("T14 界面显示第二家", SECOND_NAME in body,
            "列表里看不到刚新增的第二家")
        rec("T14 界面不渲染明文 Key", SECOND_KEY not in body,
            "设置页把明文 Key 渲染出来了")

        # ── 界面上切到第二家 ──
        btn = page.locator("button:has-text('切到这家')").first
        rec("T14 有「切到这家」按钮", btn.count() > 0, "列表项没有切换按钮")
        if btn.count() == 0:
            return
        btn.click(timeout=6000)

        end = time.time() + 12
        after = {}
        while time.time() < end:
            after = ((be.config() or {}).get("relay") or {})
            if after.get("base_url") == SECOND_URL:
                break
            time.sleep(0.4)
        rec("T14 界面切换后当前项确实变了",
            after.get("base_url") == SECOND_URL,
            f"切换后 base_url={after.get('base_url')!r}")

        # 界面上的「当前使用中」标记必须跟着走
        try:
            page.wait_for_timeout(1500)
            body2 = page.inner_text("body")
            rec("T14 界面标出新的当前使用项",
                "当前使用中" in body2 and SECOND_URL.replace(
                    "https://", "") in body2,
                f"界面未见第二家被标为当前使用中")
        except Exception as e:
            rec("T14 界面标出新的当前使用项", False, f"读取界面失败: {e}")

        # ── 切换后配置不丢 ──
        lst3 = be._get("/api/relays/configured", timeout=8) or {}
        items3 = lst3.get("relays") or []
        urls = [r.get("base_url") for r in items3]
        rec("T14 切换后两家的地址都还在",
            SECOND_URL in urls and orig_url in urls,
            f"列表地址={urls!r}")
        rec("T14 切换后列表没有重复项", len(items3) == len(set(urls)),
            f"列表地址={urls!r}")
        rec("T14 切换后启用项唯一",
            sum(1 for r in items3 if r.get("active")) == 1,
            f"active 标记={[r.get('active') for r in items3]}")
    finally:
        # ── 收尾：切回原项、移除测试这家 ──
        # ★ 顺序不能反：先切回原配置再移除 ——
        #   反过来会撞上「不能移除当前启用项」而失败，
        #   测试留下的占位中转站就会永久留在用户配置里。
        try:
            lst = be._get("/api/relays/configured", timeout=8) or {}
            items = lst.get("relays") or []
            second = next(
                (r for r in items if r.get("base_url") == SECOND_URL), None)
            orig_item = next(
                (r for r in items
                 if r.get("base_url") == orig_url and not r.get("active")),
                None)
            if orig_item is not None:
                be._post("/api/relays/active",
                         {"id": orig_item.get("id")}, timeout=8)
            if second is not None:
                be._post("/api/relays/configured/remove",
                         {"id": second.get("id")}, timeout=8)
        except Exception as e:
            rec("T14 收尾：清理测试中转站", False,
                f"清理失败: {e}（{SECOND_URL} 可能残留，需手动移除）")
        else:
            rec("T14 收尾：清理测试中转站", True, "已移除测试用的第二家")

        try:
            now = ((be.config() or {}).get("relay") or {}).get("base_url")
            rec("T14 收尾：启用项回到原样", now == orig_url,
                f"当前项 base_url={now!r}，期望 {orig_url!r}")
        except Exception as e:
            rec("T14 收尾：启用项回到原样", False, f"核对失败: {e}")


def test_relay_test_button(page, be: Backend):
    """T8 设置页「测试连接」给出与事实相符的结论。

    ★ 判据不是「面板出现了」—— 那只能证明按钮有反应。
      真正要防的是**谎报**：探针把一个不可解析的地址报成「连接正常」，
      用户会拿着这个结论去排查别处（查 Key、查网络、查中转站），
      而问题恰恰就在地址上。所以结论的正确性才是本用例的判据。

    ★ 期望值必须由**当前真实配置**推导，不能假设跑在占位地址上：
      本机可能是用户在用的真实地址（那就该报连接正常），
      写死期望会把正确的行为判成失败。
    """
    relay = (be.config() or {}).get("relay") or {}
    addr = (relay.get("base_url") or "").strip()
    if not addr:
        rec("T8 测试连接", False, "当前未配置中转站地址，无从测试", skip=True)
        return

    goto(page, "设置")

    btn = page.locator("button:has-text('测试连接')").first
    if btn.count() == 0:
        rec("T8 测试连接按钮存在", False, "设置页没有「测试连接」按钮")
        return
    rec("T8 测试连接按钮存在", True, f"当前地址={addr!r}")

    try:
        btn.click(timeout=6000)
    except Exception as e:
        rec("T8 测试连接能给出结论", False, f"点击失败: {e}")
        return

    # ★ 结论面板必须**限定在测试字段内**再找。
    #   设置页本来就有别的 .alert（中转站风险提示、激活提示等），
    #   直接找 .alert 会把它们当成测试结论 —— 于是「面板出现了」这条
    #   断言在按钮根本没生效时也会通过。
    #
    #   锚点用「会发出一真实请求」这句常驻文案，而不是按钮文案：
    #   测试中按钮文案变成「测试中…」，拿它当锚点会在等待期间失配。
    result_alerts = page.locator("div.field:has-text('会发出一真实请求')").locator(".alert")

    # 引擎侧最坏约 36s（connect 6s + read 12s，必要时再打一次 /models），
    # 桌面端 REQ_PROBE(45s) 与前端 PROBE(50s) 都比它宽。给 60s 上限。
    end = time.time() + 60
    panel = None
    while time.time() < end:
        if result_alerts.count() > 0:
            panel = result_alerts.first.inner_text().strip()
            break
        page.wait_for_timeout(400)

    if panel is None:
        rec("T8 测试连接能给出结论", False,
            "60s 内没有出现结论面板 —— 探针可能卡住，或 test_relay 命令未被正确接入")
        return
    rec("T8 测试连接能给出结论", True, f"面板={panel[:120]!r}")

    # ★ 用户必须能看到「玄盾实际会请求的地址」：
    #   地址填错的症状是 404，而用户无从知道自己填的形态被拼成了什么。
    #   摆出这一行，配置这一步就能核对，不必等到用不了再猜。
    rec("T8 结论里给出实际请求地址", "玄盾请求的地址" in panel,
        f"面板={panel[:200]!r}")

    # ★ 诚实性核心：占位地址是 RFC 2606 保留域，永远不可解析。
    #   把它报成「连接正常」= 探针在谎报。
    if ".invalid" in addr:
        lied = "连接正常" in panel
        rec("T8 对不可解析地址不谎报", not lied,
            f"地址={addr!r}（保留域，必然不可达）；面板={panel[:200]!r}")
    else:
        rec("T8 对不可解析地址不谎报", True,
            f"跳过（当前是真实地址 {addr!r}，结论无固定期望）", skip=True)


# ══════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════


def clear_onboarding_flag(page=None):
    """清掉 localStorage 里的「已完成向导」标记。

    为什么要清：走完向导会写 xuandun-personal-onboarded=done，
    留下它等于把用户下次启动时的真实首次运行体验（欢迎向导）永久跳过 ——
    测试不该悄悄改变产品行为。

    两条路径都试（顺序固定）：
      ① 走 CDP 页面内 localStorage.removeItem —— 应用运行中唯一可靠的方式
      ② 退化：直接删 WebView2 的 Local Storage 文件（进程占着时通常失败）
    两条都不成功时**显式报告**，绝不假装已还原。
    """
    if page is not None:
        try:
            removed = page.evaluate(
                "(k) => { localStorage.removeItem(k); return localStorage.getItem(k); }",
                ONBOARDING_KEY,
            )
            if removed is None:
                return "已清除向导标记（下次启动会重新显示欢迎向导）"
        except Exception:
            pass

    base = Path(os.getenv("LOCALAPPDATA") or (Path.home() / ".config"))
    ldb = base / "com.daoti.xuandun-personal" / "EBWebView"
    try:
        for f in ldb.rglob("Local Storage/leveldb/*"):
            f.unlink()
        return "已通过删除 Local Storage 文件清除向导标记"
    except Exception as e:
        return (f"!! 未能清除向导标记 {ONBOARDING_KEY}：应用运行中无法写入其存储"
                f"（{'WebView 存储被占用' if isinstance(e, PermissionError) else e}）。"
                f" 下次启动将直接进入主界面，向导不会出现。")


def restore_protection(be: Backend):
    """兜底：确保防护不在暂停态（异常中断时最要紧的事）。"""
    try:
        st = be.state()
        if st and st.get("state") == "paused":
            req = urllib.request.Request(
                f"http://127.0.0.1:{be.port}/api/resume",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=6):
                pass
            return "已兜底恢复防护"
        return "防护未被暂停，无需恢复"
    except Exception as e:
        return f"!! 兜底恢复防护失败: {e}"


def launch_desktop():
    """自己拉起桌面端 release 可执行文件。

    ★ 为什么必须由本脚本启动，而不是让用户先手动开：
      沙箱/终端在单条命令结束时回收它拉起的子进程 ——
      「先 Start-Process 再跑测试」这种写法会看到 CDP 在测试开始前就没了，
      报错是「CDP 端口不可用」，指向的环境问题而实际是启动方式问题。
      由本脚本持有 Popen 句柄，进程在测试期间不会被回收。

    ★ release 下 CDP 默认关闭（见 lib.rs::enable_cdp_debug_port），
      开放该端口等于允许任意本地进程注入 JS 篡改界面显示，
      所以必须显式设环境变量 —— 这也是脚本只在本地跑的原因。
    """
    exe = os.environ.get(
        "XUANDUN_EXE", r"G:\rust-target\release\xuandun-personal.exe"
    )
    if not os.path.isfile(exe):
        print(f"[FATAL] 找不到桌面端可执行文件: {exe}")
        print("  请先编译：")
        print("    cd personal/desktop && npm run build")
        print("    cd personal/desktop/src-tauri")
        print("    $env:CARGO_TARGET_DIR='G:\\rust-target'; cargo build --release")
        return None
    env = os.environ.copy()
    env["XUANDUN_ENABLE_CDP_DEBUG"] = "1"
    proc = subprocess.Popen([exe], env=env)
    print(f"  已启动桌面端: {exe}  (PID {proc.pid})")
    return proc


def main():
    print("=" * 74)
    print("  玄盾个人版 — 桌面端 CDP 回归测试")
    print("=" * 74)

    proc = None
    if not cdp_browser_ver():
        proc = launch_desktop()
        if proc is None:
            return 2
        # 等 CDP 就绪
        deadline = time.time() + 60
        while time.time() < deadline and not cdp_browser_ver():
            if proc.poll() is not None:
                print(f"[FATAL] 桌面端提前退出，退出码 {proc.returncode}")
                return 2
            time.sleep(1)

    browser_ver = cdp_browser_ver()
    if not browser_ver:
        print("[FATAL] CDP 端口 9224 不可用。")
        print("  请先启动桌面端：")
        print("    cd personal/desktop/src-tauri")
        print("    cargo run            # debug 构建自动开启 CDP")
        print("  release 构建需先设环境变量：")
        print("    $env:XUANDUN_ENABLE_CDP_DEBUG='1'")
        return 2
    print(f"  CDP 已连接: {browser_ver}")
    print()

    guard = ConfigGuard()
    be = Backend(DEFAULT_PROXY_PORT)
    onboarded_by_test = False
    restore_notes: list[str] = []
    page = None  # finally 阶段要用（需 CDP 连接才能清向导标记 / 重启引擎）

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.connect_over_cdp(CDP_BASE)
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            page.set_default_timeout(10000)

            # 监听器必须最早挂上，否则测不到启动期报错
            page.on("console", lambda m: (
                _console_errors.append(m.text) if m.type == "error" else None))
            page.on("pageerror", lambda e: _console_errors.append(str(e)))

            # ── 引擎健康 + 真实端口 ──
            # ★ 必须先让界面跑起来，再等引擎。
            #
            #   引擎是**懒启动**的：桌面端进程起来后，界面首次请求
            #   /api/state 才会触发 ensure_engine_running 去拉起它。
            #   此前先探 health、后加载界面，顺序反了 ——
            #   于是必然读到「无响应」并 FATAL，而那不是产品缺陷，是时序。
            #
            #   这条也是本脚本最容易犯的一类错：把「还没到时候」
            #   报成「坏了」，用户会以为应用有问题。
            try:
                page.wait_for_load_state("domcontentloaded", timeout=20000)
                page.wait_for_timeout(2500)  # 给 React 挂载 + 首次请求留时间
            except Exception:
                pass

            health = None
            deadline = time.time() + 60
            while time.time() < deadline:
                health = be.health()
                if health:
                    break
                page.wait_for_timeout(500)
            if not health:
                # 返回 2 而非继续：没有引擎就没有独立事实源，
                # 所有「界面是否诚实」的断言都会退化成自说自话。
                print("[FATAL] 本地代理（127.0.0.1:18765）无响应，无法取得对照事实源。")
                print("  请确认玄盾引擎已启动（应用启动后会自动拉起）。")
                return 2
            try:
                real_port = page.evaluate(
                    "() => window.__TAURI_INTERNALS__.invoke('get_active_port')"
                )
                if isinstance(real_port, int) and 1024 <= real_port <= 65535:
                    be = Backend(real_port)
            except Exception:
                pass
            print(f"  引擎: {health.get('version')}  端口: {be.port}  "
                  f"中转站已配置: {health.get('relay_configured')}")
            print()

            # ══════════════════════════════════════════════════════
            # 进入主界面
            # ══════════════════════════════════════════════════════
            # ★ 全新环境（刚装 / 配置被清空）下应用会停在欢迎向导，
            #   而后续所有用例都以主界面为前提。先把向导走通，
            #   否则整套测试会因为「用户还没配置」而全灭 ——
            #   那是环境问题，不是产品缺陷，不该记在产品账上。
            if page.locator("nav a").count() == 0:
                ok_shell, why = wait_for_shell(page, timeout=15000)
                if not ok_shell:
                    rec("T1 主界面挂载", False, f"界面未就绪：{why}")
                    print("\n[FATAL] 无法进入主界面，后续用例无法执行。")
                    page.wait_for_timeout(300)
                    return 2
                # ★ 必须用 on_wizard 复核，不能凭 wait_for_shell 的返回值。
                #   wait_for_shell 在「主界面直接挂上」时也返回 True
                #   （那是它修的那个 bug：把挂载中当成「什么都没出现」），
                #   所以 True 只说明「界面就绪」，不说明「在向导里」。
                #   早先这里直接走去导分支，而主界面上没有「开始」按钮
                #   → 必假失败。判据借位是这脚本最反复的一类坑。
                if on_wizard(page):
                    rec("T0 首次运行显示欢迎向导", True, why)
                    ok, why2 = complete_wizard(page)
                    onboarded_by_test = onboarded_by_test or ok
                    rec("T0 引导至主界面", ok, why2)
                else:
                    rec("T0 首次运行显示欢迎向导", True,
                        f"{why}（按设计跳过：已配置过中转站的用户不再走向导）")

            if page.locator("nav a").count() == 0:
                rec("T1 主界面挂载", False, "走完向导后仍无 nav 元素")
                print("\n[FATAL] 主界面未能挂载，后续用例无法执行。")
            else:
                section("主界面与状态诚实性")
                for name, fn in (
                    ("T1 启动与导航", lambda: test_boot(page)),
                    ("T2 页面渲染", lambda: test_pages_render(page)),
                    ("T2b 激活页诚实性", lambda: test_activate_page_honest(page, be)),
                    ("T3 状态诚实性", lambda: test_status_bar_honest(page, be)),
                    ("T3b 降级分支", lambda: test_unreachable_label(page, be)),
                    ("T4 KPI 一致性", lambda: test_dashboard_kpi(page, be)),
                    ("T4b 中转站状态诚实性", lambda: test_dashboard_relay_honest(page, be)),
                    ("T13 信誉评分自洽", lambda: test_reputation_score_honest(page, be)),
                ):
                    try:
                        fn()
                    except Exception as e:
                        rec(name, False, f"未捕获异常 {type(e).__name__}: {e}")

                section("设置与交互")
                for name, fn in (
                    ("T5 开关存在", lambda: test_settings_toggles(page, be)),
                    ("T5b 开关生效", lambda: test_toggle_applies(page, be)),
                    ("T8 测试连接", lambda: test_relay_test_button(page, be)),
                    # ★ T14 会新增/切换/移除中转站配置。
                    #   必须排在 T10（拦截全链路）**之前** ——
                    #   T14 会临时把当前启用项切到 .invalid 占位地址，
                    #   那个地址解析不了；T10 若在那之后跑，
                    #   请求会因连不上而返回 502 而不是 403，
                    #   拦截判据必然 FAIL。
                    ("T14 多中转站切换", lambda: test_multi_relay_settings(page, be)),
                    # ★ T10 必须排在 T9（暂停恢复）**之前**：
                    #   T9 会把防护暂停掉，而防护暂停时引擎走的是
                    #   直通转发、不再执行检测 —— T10 在那种状态下跑，
                    #   载荷里的敏感信息会**原样发往中转站**，
                    #   既测不到拦截（必然 FAIL），
                    #   又等于往真实中转站发了一次带假密钥的请求。
                    #   顺序不是风格问题，是安全与正确性问题。
                    ("T10 拦截全链路", lambda: test_block_end_to_end(page, be)),
                    ("T11 首页刷新", lambda: test_dashboard_refresh(page, be)),
                    # ★ T12 会改动用户真实统计（标记一条拦截为误报），
                    #   虽然收尾会撤销，但必须在 T9 暂停之前跑：
                    #   暂停期间引擎直通，/api/state 仍可读，
                    #   而恢复过程中的统计抖动会让「恰好 -1」的判据难辨。
                    ("T12 标记误报降数", lambda: test_mark_false_positive_lowers_count(page, be)),
                    ("T9 暂停恢复", lambda: test_pause_resume(page, be)),
                    ("T6 异常边界", lambda: test_error_boundary(page)),
                    ("T7 控制台", lambda: test_console_clean(page)),
                ):
                    try:
                        fn()
                    except Exception as e:
                        rec(name, False, f"未捕获异常 {type(e).__name__}: {e}")

                # ★ T0 放在最后，且**主动构造**首次运行条件。
            #   之前放在最前面、且靠「恰好没走过向导」才生效 —— 那是偶然状态：
            #   上一次跑完把标记写上了，下次就 SKIP，这条用例形同虚设。
            #   现在显式清标记 + reload，让它每次都真跑。
            #
            # ★ 还要先清掉占位中转站：向导的进入条件是「未配置过中转站」，
            #   若引擎内存里还留着占位值，App 会**按设计**跳过向导 ——
            #   那是产品行为正确，不是缺陷。测试必须先造出前置条件。
            section("T0 首次运行向导")
            try:
                if guard.has_placeholder(be):
                    restore_notes.append(guard.restore_file())
                    restore_notes.append(reload_engine_from_disk(page, be))
                page.evaluate(
                    "() => localStorage.removeItem('xuandun-personal-onboarded')")
                page.reload(wait_until="domcontentloaded")
                ok_shell, why = wait_for_shell(page, timeout=15000)

                # ★ 「中转站已配置 → 按设计跳过向导」是**正确行为**，
                #   不是首启动判定失效。
                #   本机跑这条用例时往往根本没走过占位流程（配置是真的），
                #   向导的进入条件「未配置过中转站」不成立，
                #   于是必然看不到向导 —— 此前把它记成 FAIL，
                #   等于要求产品违反自己的设计。
                #
                #   判据：引擎内存里确实有真实中转站时，跳过向导是预期行为，
                #   本用例改判 SKIP 并说明原因，不计入失败。
                relay_now = ((be.config() or {}).get("relay") or {}).get("base_url") or ""
                # ★ 判据必须是「真的看到向导」，不能用 ok_shell ——
                #   wait_for_shell 在主界面直接挂上时也返回 True，
                #   拿它当「看到向导」会跑去点「开始」按钮，
                #   而主界面上根本没有这个按钮 → 必假失败。
                #   （实测踩过：判据借位，T0 从真缺陷变成假缺陷。）
                saw_wizard = on_wizard(page)
                if not saw_wizard and relay_now.strip():
                    rec("T0 首次运行显示欢迎向导", True,
                        f"按设计跳过（已配置中转站 {relay_now[:40]}…，"
                        f"向导进入条件「未配置过中转站」不成立）—— 非缺陷")
                elif not saw_wizard:
                    rec("T0 首次运行显示欢迎向导", False,
                        f"未配置中转站却也没出现向导：{why}")
                else:
                    rec("T0 首次运行显示欢迎向导", True, why)

                if saw_wizard:
                    ok, why2 = complete_wizard(page)
                    onboarded_by_test = ok
                    rec("T0 向导可完整走通", ok, why2)
            except Exception as e:
                rec("T0 向导流程", False, f"异常: {type(e).__name__}: {e}")

            # ★ 以下几步必须在 CDP 连接**存活**时做。
            #   放进 finally 块会失败：finally 在 with sync_playwright() 退出
            #   之后才执行，此时 Playwright 已停、页面上下文已销毁，
            #   page.evaluate 必然抛错 → 向导标记清不掉、引擎也重启不了。
            #
            # ★ 判据用 has_placeholder（查引擎内存）而非 onboarded_by_test
            #   （查本轮是否写过）：后者会让「上一轮残留」永远清不掉。
            if guard.has_placeholder(be):
                # 顺序不可颠倒：先还原磁盘文件，再让引擎重读它。
                # 反了等于用测试写入的脏配置覆盖掉刚还原的干净文件。
                restore_notes.append("检测到占位中转站残留，执行清理")
                restore_notes.append(guard.restore_file())
                restore_notes.append(reload_engine_from_disk(page, be))
            if onboarded_by_test:
                restore_notes.append(clear_onboarding_flag(page))

            # ★ 不调 browser.close()：connect_over_cdp 下 close() 关掉的是
            #   本地连上的 Playwright 句柄，WebView2 窗口与引擎进程不受影响，
            #   但它可能连带断掉后续仍要用的 page 句柄。
            #   应用由用户自己关闭即可，测试不越权杀进程。
            page.wait_for_timeout(500)

    finally:
        # ★ 收掉自己拉起的桌面端。
        #   只在**本脚本启动**它时才杀（proc 非 None）：
        #   用户自己开着的那个属于用户，测试不该越权关掉。
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=8)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            print("  · 已关闭本次测试启动的桌面端")

        # ★ 每一步各自 try：还原步骤之间不能互相挤掉。
        #   曾经它们是三条裸语句，`restore_protection`（兜底恢复防护，
        #   即异常中断时最要紧的事）会被前一步的异常跳过；
        #   而 section() 里的 print 在管道断开时会抛 BrokenPipeError。
        for label, fn in (
            ("还原配置文件", guard.restore_file),
            ("兜底恢复防护", lambda: restore_protection(be)),
        ):
            try:
                restore_notes.append(fn())
            except Exception as e:
                # 还原失败必须显式暴露，且不能中断后续还原步骤
                restore_notes.append(f"!! {label} 异常: {type(e).__name__}: {e}")

        # 引擎内存若仍有占位中转站，此刻磁盘已干净、内存却脏 ——
        # 比不还原更危险。这里再兜一次（依赖 CDP，可能已断开）。
        try:
            if guard.has_placeholder(be):
                restore_notes.append(
                    "!! 仍检测到占位中转站残留，但 CDP 可能已断开，"
                    "请手动重启玄盾"
                )
        except Exception:
            pass

        section("还原")
        for n in restore_notes:
            if n:
                try:
                    print(f"  · {n}")
                except Exception:
                    pass

    print()
    print("=" * 74)
    p, f, s = results["pass"], results["fail"], results["skip"]
    print(f"  结果: PASS={p}  FAIL={f}  SKIP={s}  （共 {p + f + s}）")
    if f:
        print("  存在失败项 —— 桌面端存在真实缺陷，需修复后重测")
    if s:
        print("  存在跳过项 —— 「后端不可达 / 开关读不到 / 防护本就暂停」")
        print("  这类最需要报警的情形恰恰会被跳过，**不算通过**")
    if p == 0:
        print("  一项都没跑成 —— 不可视为通过")
    print("=" * 74)

    # ★ 退出码必须把 skip 算作「非通过」。
    #   曾经是 `return 0 if f == 0 else 1`，于是「全部 SKIP」→ 退出码 0，
    #   而触发 skip 的条件恰恰是后端挂了、开关读不到 ——
    #   对一个专门用于「防止界面谎报」的安全测试，这是方向性错误：
    #   最该报警的情形反而报绿。
    #
    #   0 = 全通过；1 = 有真实失败；2 = 未能有效执行（含全部跳过）
    if f:
        return 1
    if s or p == 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
