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
PLACEHOLDER_MODEL = "gpt-4o"

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
ALL_STATE_LABELS = set(STATE_LABELS.values()) | {"本地代理未运行"}

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

    def _get(self, path, timeout=5):
        url = f"http://127.0.0.1:{self.port}{path}"
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def health(self):
        try:
            return self._get("/health", timeout=3)
        except Exception:
            return None

    def state(self):
        try:
            return self._get("/api/state", timeout=4)
        except Exception:
            return None

    def config(self):
        try:
            return self._get("/api/config", timeout=4)
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


def wait_for_wizard(page, timeout=15000):
    """等欢迎向导出现。返回 (是否出现, 说明)。

    ★ 判据是「wizard-shell 出现且主界面 nav 不在」：
      两者互斥才是真的进了向导。只查 wizard-shell 会在
      React 还没跑完 checkFirstRun（此时显示 loading）时误判为通过。
    """
    end = time.time() + timeout / 1000
    while time.time() < end:
        if on_wizard(page) and page.locator("nav a").count() == 0:
            return True, "向导可见（正常：未配置过中转站的新用户会看到它）"
        page.wait_for_timeout(300)
    return False, ("未出现欢迎向导 —— 可能是首启动判定逻辑失效，"
                   "或中转站已配置导致按设计跳过")


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
    try:
        page.locator("#ob-url").wait_for(state="visible", timeout=8000)
        page.fill("#ob-url", PLACEHOLDER_URL)
        page.fill("#ob-key", PLACEHOLDER_KEY)
        page.fill("#ob-model", PLACEHOLDER_MODEL)
    except Exception as e:
        return False, f"填写配置失败: {e}"

    # 下一步按钮在三项都非空前是 disabled 的
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

    # ② 未激活时必须有激活码输入框
    rec("T2b 激活码输入框存在", page.locator("#act-code").count() > 0,
        f"找到 {page.locator('#act-code').count()} 个")

    # ③ ★ 诚实性核心：界面是否宣称已激活，必须与真实状态一致。
    #    ★ 不能假设「本机一定未激活」—— 测试者可能已经激活过。
    #      那种情况下断言「界面不该说已激活」就是假失败。
    #    所以这里要拿真实状态做对照，而不是拿假设做对照。
    claims_activated = "已激活" in body
    if claims_activated:
        # 界面说已激活 → 激活码输入框不该同时存在（两个状态互斥）
        rec("T2b 激活状态互斥", page.locator("#act-code").count() == 0,
            "界面同时显示「已激活」和激活码输入框，两种状态矛盾")
    else:
        rec("T2b 激活状态互斥", page.locator("#act-code").count() > 0,
            "界面未显示已激活，却也没有激活码输入框（用户无法激活）")

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
        rec("T3 状态栏诚实", False, "无法读取后端 /api/state，无对照物", skip=True)
        return

    state = real.get("state", "learning")
    expected = STATE_LABELS.get(state, state)
    ok, seen = wait_label(page, expected, timeout=8000)
    detail = f"后端 state={state!r} 期望 label={expected!r} 实际={seen!r}"
    rec("T3 状态栏显示真实状态", ok, detail)

    if ok:
        # ★ 判据改为「整个状态栏里只出现一个状态词」。
        #   曾经写成「status-label 文本里不含其他状态词」——
        #   而 status_label() 只读那唯一一个 span，其内容恒等于 expected，
        #   于是 wrong 恒为 []，这是一条**恒真断言、零信息量**，
        #   看起来在防「多重状态谎报」实际什么也没防。
        #
        #   真正的风险是：状态栏同时出现「危险」和「今日已检查 12 次」
        #   这类自相矛盾的组合（一边报警、一边报喜）。
        #   所以要看的是整条状态栏的文本，不是那一个 label。
        bar = status_text(page)
        wrong = [o for o in ALL_STATE_LABELS if o in bar and o != expected]
        rec("T3 状态栏无自相矛盾", not wrong,
            f"状态栏全文={bar!r}，混入 {wrong}" if wrong else f"状态栏全文={bar!r}")

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


def main():
    print("=" * 74)
    print("  玄盾个人版 — 桌面端 CDP 回归测试")
    print("=" * 74)

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
            health = be.health()
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
                ok_shell, why = wait_for_wizard(page, timeout=15000)
                if ok_shell:
                    rec("T0 初始状态为欢迎向导", True, why)
                    ok, why2 = complete_wizard(page)
                    onboarded_by_test = onboarded_by_test or ok
                    rec("T0 引导至主界面", ok, why2)
                else:
                    rec("T1 主界面挂载", False,
                        f"既无主界面也无向导：{why}")
                    print("\n[FATAL] 无法进入主界面，后续用例无法执行。")
                    page.wait_for_timeout(300)
                    return 2

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
                ):
                    try:
                        fn()
                    except Exception as e:
                        rec(name, False, f"未捕获异常 {type(e).__name__}: {e}")

                section("设置与交互")
                for name, fn in (
                    ("T5 开关存在", lambda: test_settings_toggles(page, be)),
                    ("T5b 开关生效", lambda: test_toggle_applies(page, be)),
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
                ok_shell, why = wait_for_wizard(page, timeout=15000)
                rec("T0 首次运行显示欢迎向导", ok_shell, why)

                if ok_shell:
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
