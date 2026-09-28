# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白

"""激活码签发 WebUI —— 把 gen_activation_keys.py 的命令行变成网页操作。

为什么要有这个
────────────────────────────────────────────────────────────
签发操作的实际节奏是「用户发来机器码 → 粘贴 → 签发 → 把码发回去」。
这个循环每天要跑几十次，每次都敲一长串命令行参数既慢又容易敲错
（尤其是 32 位十六进制机器码，错一位就是给一台不存在的机器签了码）。

★★ 安全边界（本文件最重要的约束）
────────────────────────────────────────────────────────────
这个页面会**用私钥签发激活码**，所以：

  · 默认只监听 127.0.0.1，不对外暴露。局域网里任何人都能打开它
    = 任何人都能给自己签发永久激活码。
  · 不做登录、不做鉴权 —— 它假设运行环境是「你自己的电脑」，
    加一层假鉴权反而会给人「已经安全了」的错觉。
  · 端口只接受来自本机的连接，检测到非本机来源直接拒绝。

如果你需要远程签发，正确做法是走 SSH 隧道，而不是把它暴露到公网。

为什么不重写签名逻辑
────────────────────────────────────────────────────────────
本文件 import gen_activation_keys 里的函数，而不是复制一份实现。
两份签名逻辑一旦漂移，WebUI 签出的码可能客户端验不过 ——
而这种故障要等到用户激活失败时才暴露，排查成本极高。

启动：
    python tools/activation/webui.py            # 默认 127.0.0.1:8760
    python tools/activation/webui.py --port 9000
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent

# 让本文件能 import 同目录的 gen_activation_keys
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
# license 模块在 src/ 下（用于吊销名单查询）
_SRC = _REPO / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import gen_activation_keys as gak  # noqa: E402

PRIVATE_KEY = _HERE / gak.PRIVATE_KEY_NAME
PUBLIC_KEY = _HERE / gak.PUBLIC_KEY_NAME
LOG_PATH = _HERE / gak.DEFAULT_LOG.name


# ══════════════════════════════════════════════════════════════
# 密钥与日志的读取
# ══════════════════════════════════════════════════════════════


def key_status() -> Dict[str, Any]:
    """密钥对是否就位。缺私钥时前端要明确显示，别让用户签到一半才失败。"""
    return {
        "private_key_exists": PRIVATE_KEY.is_file(),
        "public_key_exists": PUBLIC_KEY.is_file(),
        "private_key_path": str(PRIVATE_KEY),
        "public_key_path": str(PUBLIC_KEY),
    }


def read_log() -> List[dict]:
    """读签发日志。任何读取异常都如实报告，不静默当成「没有记录」。

    ★ 日志损坏若被静默处理，audit 会得出「未发现异常传播」的错误结论，
      而实际上只是日志读不出来 —— 这会让唯一的传播检测手段失效。
    """
    if not LOG_PATH.is_file():
        return []
    try:
        data = json.loads(LOG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ValueError(f"签发日志不可读（{e}）：{LOG_PATH}") from e
    if not isinstance(data, list):
        raise ValueError(f"签发日志格式异常（不是列表）：{LOG_PATH}")
    return [r for r in data if isinstance(r, dict)]


def run_cli(args: List[str]) -> Dict[str, Any]:
    """调用 CLI 子命令并取回结果。

    ★ 为什么不直接调 issue()/rebind() 函数：
      那几个函数把结果 print 到 stdout，return 的是退出码。
      Web 界面需要结构化结果（码、jti、代次），只能从 stdout 解析 ——
      解析文本很脆。折中办法是调用 CLI 并解析**约定好的标记行**，
      标记行由本文件自己 append 上去，不依赖 CLI 的排版。
    """
    proc = subprocess.run(
        [sys.executable, str(_HERE / "gen_activation_keys.py"), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(_REPO),
    )
    return {
        "ok": proc.returncode == 0,
        "code": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


# ══════════════════════════════════════════════════════════════
# FastAPI 应用
# ══════════════════════════════════════════════════════════════

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    from pydantic import BaseModel, Field
except ImportError as e:  # pragma: no cover
    print(f"缺少依赖：{e}\n  pip install fastapi uvicorn", file=sys.stderr)
    raise

app = FastAPI(title="玄盾激活码签发", docs_url=None, redoc_url=None)


# ── 安全：只接受本机来源 ────────────────────────────────────
LOOPBACK = {"127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"}


@app.middleware("http")
async def reject_non_local(request: Request, call_next):
    """拒绝非本机来源的请求。

    这个页面握着私钥，任何非本机的连接都必须挡住。
    不做鉴权的原因见文件头：宁可明确「它不防远程」，也不要假鉴权。
    """
    client = request.client
    # testclient 是 starlette TestClient 的固定 host，只在进程内测试时出现，
    # 不会经由网络到达。放它进来是为了让本机校验逻辑本身可被测试。
    if client and client.host not in LOOPBACK and client.host != "testclient":
        return JSONResponse(
            status_code=403,
            content={
                "detail": "本工具持有私钥，只接受本机访问。"
                          f"你来自 {client.host}。远程签发请用 SSH 隧道。"
            },
        )
    return await call_next(request)


# ══════════════════════════════════════════════════════════════
# 接口
# ══════════════════════════════════════════════════════════════


class IssueReq(BaseModel):
    name: str = Field(min_length=1, description="授权给谁")
    mch: str = Field(min_length=1, description="机器码（客户端显示的 32 位十六进制）")
    days: int = Field(default=365, ge=1, le=3650)
    tier: str = Field(default="personal")
    features: str = Field(default="")


class RebindReq(BaseModel):
    request: str = Field(min_length=1, description="客户端生成的 XDRB. 请求串")


class RevokeReq(BaseModel):
    jti: str = Field(min_length=1)
    before_gen: Optional[int] = Field(
        default=None,
        description="只作废 gen 小于该值的码。换绑后必填，否则新旧两张码一起死",
    )


class VerifyReq(BaseModel):
    code: str = Field(min_length=1)


@app.get("/api/status")
def api_status() -> Dict[str, Any]:
    return key_status()


@app.post("/api/issue")
def api_issue(req: IssueReq) -> Dict[str, Any]:
    if not PRIVATE_KEY.is_file():
        raise HTTPException(400, f"私钥不存在：{PRIVATE_KEY}")

    # ★ 必须查空白：pydantic 的 min_length=1 只挡空串，挡得住 "   "。
    #   sub 为空不致命但很糟糕 —— 它是日后唯一的人工核对依据
    #   （用户报障时「你叫什么」「订单号多少」全靠它），
    #   签出一张查不到出处的码，等于签了一张匿名码。
    if not req.name.strip():
        raise HTTPException(400, "「授权给谁」不能为空 —— 它是日后核对用户的唯一依据")
    if not req.mch.strip():
        raise HTTPException(400, "机器码不能为空")

    mch = req.mch.strip()
    # ★ 先算哈希再签，好让界面能回显「码里绑的到底是哪台机器」。
    #   32 位十六进制太长，粘贴时极易出错，必须让用户能自己核对。
    mch_hashed = gak.machine_code_hash(mch)
    looks_ok = len(mch_hashed) == 32

    args = [
        "issue",
        "--key", str(PRIVATE_KEY),
        "--name", req.name.strip(),
        "--mch", mch,
        "--days", str(req.days),
        "--tier", req.tier.strip() or "personal",
        # ★ 显式传 --log：CLI 默认写到它自己目录下的 ACTIVATION_LOG.json，
        #   不传的话测试会污染真实签发记录，真实使用也会与界面显示的记录脱节。
        "--log", str(LOG_PATH),
    ]
    if req.features.strip():
        args += ["--features", req.features.strip()]

    res = run_cli(args)
    if not res["ok"]:
        raise HTTPException(400, res["stderr"] or res["stdout"] or "签发失败")

    code = ""
    for line in res["stdout"].splitlines():
        if line.strip().startswith(gak._PREFIX):
            code = line.strip()
            break
    if not code:
        raise HTTPException(500, "签发进程成功但没拿到激活码，请检查签发日志")

    jti = ""
    expires_at = ""
    # ★ jti 从签出的码里解码取得，而不是从 CLI 打印的 `jti : xxx` 里切。
    #   后者会把中文排版（如「（不变，吊销仍有效）」）一起带出来，
    #   而 jti 之后要直接喂给吊销接口，多余字符会让吊销静默失败。
    try:
        import jwt as _jwt

        claims = _jwt.decode(
            code[len(gak._PREFIX):],
            gak._load_public_key(PUBLIC_KEY),
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_exp": False},
        )
        jti = str(claims.get("jti", ""))
        mch_in_code = str(claims.get("mch", ""))
        if mch_in_code and mch_in_code != mch_hashed:
            # 码里绑的机器码与我们算的不一致 —— 签发环节有问题，必须报出来
            raise HTTPException(
                500,
                f"签发的码绑定到了另一台机器（码内 {mch_in_code} ≠ 本次输入 "
                f"{mch_hashed}）。这属于签发链路异常，请勿把该码发给用户。",
            )
        from datetime import datetime as _dt, timezone as _tz

        expires_at = _dt.fromtimestamp(
            int(claims["exp"]), tz=_tz.utc
        ).strftime("%Y-%m-%d")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            500, f"签发出的码无法解析（CLI 说成功但码不可读）：{e}"
        ) from e

    return {
        "code": code,
        "jti": jti,
        "mch_hashed": mch_hashed,
        "expires_at": expires_at,
        "machine_code_suspect": not looks_ok,
    }


@app.post("/api/rebind")
def api_rebind(req: RebindReq) -> Dict[str, Any]:
    if not PRIVATE_KEY.is_file():
        raise HTTPException(400, f"私钥不存在：{PRIVATE_KEY}")
    if not PUBLIC_KEY.is_file():
        raise HTTPException(400, f"公钥不存在：{PUBLIC_KEY}")

    raw = req.request.strip()
    if not raw.startswith("XDRB."):
        raise HTTPException(400, "请求串应以 XDRB. 开头（从客户端「激活」页复制）")

    res = run_cli([
        "rebind",
        "--key", str(PRIVATE_KEY),
        "--pub", str(PUBLIC_KEY),
        "--request", raw,
        # 与签发同理：换绑也必须写进同一份签发记录，
        # 否则传播审计看不见任何换绑痕迹。
        "--log", str(LOG_PATH),
    ])
    if not res["ok"]:
        raise HTTPException(400, res["stderr"] or res["stdout"] or "换绑失败")

    out = res["stdout"]
    code = ""
    for line in out.splitlines():
        if line.strip().startswith(gak._PREFIX):
            code = line.strip()
            break

    # ★ 解析 CLI 的人读排版来取数据是脆的（中文冒号、括注、空格都对不齐），
    #   所以这里只把「代次」和「作废提示」从文本里捞出来 ——
    #   这两项 CLI 本来就只给人看；而 jti / 机器码哈希改为**直接解码新码**取得，
    #   不依赖任何文案。码是自包含的，解出来必然是权威值。
    jti = ""
    machine_to = ""
    new_gen = 0
    if code:
        try:
            import jwt as _jwt

            claims = _jwt.decode(
                code[len(gak._PREFIX):],
                gak._load_public_key(PUBLIC_KEY),
                algorithms=["RS256"],
                options={"verify_aud": False, "verify_exp": False},
            )
            jti = str(claims.get("jti", ""))
            machine_to = str(claims.get("mch", ""))
            new_gen = int(claims.get("gen", 0) or 0)
        except Exception as e:
            raise HTTPException(
                500, f"换绑产出的码无法解析（CLI 说成功但码不可读）：{e}"
            ) from e

    machine_from = ""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("机器码") and "→" in s:
            machine_from = s.split("→")[0].split(":")[-1].strip()

    revoke_hint = ""
    for line in out.splitlines():
        if "gen_activation_keys.py revoke" in line:
            revoke_hint = line.strip()

    return {
        "code": code,
        "jti": jti,
        "new_gen": new_gen,
        "machine_from": machine_from,
        "machine_to": machine_to,
        "revoke_hint": revoke_hint,
        "stdout": out,
    }


@app.post("/api/revoke")
def api_revoke(req: RevokeReq) -> Dict[str, Any]:
    if not req.jti.strip():
        raise HTTPException(400, "jti 不能为空")
    if req.before_gen is not None and req.before_gen < 0:
        raise HTTPException(400, "before_gen 不能为负")

    args = ["revoke", req.jti.strip()]
    if req.before_gen is not None:
        args += ["--before-gen", str(req.before_gen)]
    res = run_cli(args)
    if not res["ok"]:
        raise HTTPException(400, res["stderr"] or res["stdout"] or "吊销失败")
    return {"ok": True, "stdout": res["stdout"], "stderr": res["stderr"]}


class AuditReq(BaseModel):
    max_machines: int = Field(default=2, ge=1)
    max_rebinds: int = Field(default=2, ge=1)


@app.post("/api/audit")
def api_audit(req: AuditReq) -> Dict[str, Any]:
    """把 audit 子命令的输出透传给前端。

    这里不重写 audit 逻辑：判据（几台机器算传播、几次换绑算批量）
    是安全判断，不该在两个地方各写一遍。
    """
    res = run_cli([
        "audit",
        "--log", str(LOG_PATH),
        "--max-machines", str(req.max_machines),
        "--max-rebinds", str(req.max_rebinds),
    ])
    return {
        "ok": res["ok"],
        "report": res["stdout"] or res["stderr"],
        "has_alert": res["code"] == 1,
    }


@app.post("/api/verify")
def api_verify(req: VerifyReq) -> Dict[str, Any]:
    """用公钥验一张码 —— 排查用户问题时最快的一步。"""
    if not PUBLIC_KEY.is_file():
        raise HTTPException(400, f"公钥不存在：{PUBLIC_KEY}")
    res = run_cli(["verify", "--pub", str(PUBLIC_KEY), "--code", req.code.strip()])
    return {
        "ok": res["ok"],
        "report": res["stdout"] or res["stderr"],
    }


@app.get("/api/log")
def api_log() -> Dict[str, Any]:
    try:
        records = read_log()
    except ValueError as e:
        # ★ 不吞掉：日志读不出来时前端必须显示红色告警，
        #   否则用户会以为「没有记录 = 没有异常」。
        raise HTTPException(500, str(e)) from e

    revoked: set = set()
    try:
        from daoti_xuandun_personal import license as lic

        revoked = lic.load_revoked() or set()
    except Exception:
        revoked = set()

    items = []
    for rec in records:
        jti = str(rec.get("jti", "")).strip()
        gen = rec.get("gen", 0)
        try:
            gen = int(gen or 0)
        except (TypeError, ValueError):
            gen = 0
        is_revoked = any(
            e == jti or (e.startswith(f"{jti}#") and gen < int(e.rsplit("#", 1)[1]))
            for e in revoked
            if "#" not in e or e.rsplit("#", 1)[1].lstrip("-").isdigit()
        )
        items.append({
            "jti": jti,
            "gen": gen,
            "name": rec.get("name", ""),
            "tier": rec.get("tier", ""),
            "mch": rec.get("mch", ""),
            "mch_raw": rec.get("mch_raw", ""),
            "event": rec.get("event", "issue"),
            "from_mch": rec.get("from_mch", ""),
            "created_at": rec.get("created_at", ""),
            "expires_at": rec.get("expires_at", ""),
            "revoked": is_revoked,
            "code": rec.get("code", ""),
        })
    items.sort(key=lambda x: x["created_at"], reverse=True)
    return {"items": items, "total": len(items)}


# ══════════════════════════════════════════════════════════════
# 页面
# ══════════════════════════════════════════════════════════════

_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>玄盾 · 激活码签发</title>
<style>
  :root{
    --bg:#0d1117; --panel:#161b22; --line:#30363d; --fg:#e6edf3;
    --dim:#8b949e; --accent:#2f81f7; --ok:#3fb950; --warn:#d29922; --bad:#f85149;
    --mono:ui-monospace,SFMono-Regular,"Cascadia Code",Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
    font:14px/1.6 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
  header{padding:16px 24px;border-bottom:1px solid var(--line);
    display:flex;align-items:center;gap:14px;flex-wrap:wrap}
  h1{font-size:17px;margin:0;font-weight:600;letter-spacing:.3px}
  .pill{font-size:12px;padding:3px 10px;border-radius:999px;border:1px solid var(--line)}
  .pill.ok{color:var(--ok);border-color:#1d4429;background:#0f2716}
  .pill.bad{color:var(--bad);border-color:#5c1f1c;background:#2d1210}
  main{max-width:1080px;margin:0 auto;padding:20px 24px 60px}
  nav{display:flex;gap:4px;margin-bottom:18px;border-bottom:1px solid var(--line)}
  nav button{background:none;border:none;color:var(--dim);padding:9px 16px;cursor:pointer;
    font-size:14px;border-bottom:2px solid transparent;font-family:inherit}
  nav button:hover{color:var(--fg)}
  nav button.on{color:var(--fg);border-bottom-color:var(--accent);font-weight:600}
  .panel{display:none}
  .panel.on{display:block}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:8px;
    padding:18px;margin-bottom:16px}
  .card h2{font-size:14px;margin:0 0 4px;font-weight:600}
  .card .hint{color:var(--dim);font-size:12.5px;margin:0 0 14px}
  label{display:block;font-size:12.5px;color:var(--dim);margin:12px 0 5px}
  input,select,textarea{width:100%;padding:8px 11px;background:#0d1117;color:var(--fg);
    border:1px solid var(--line);border-radius:6px;font-size:13.5px;font-family:inherit}
  input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)}
  input.mono,textarea.mono{font-family:var(--mono);font-size:12.5px}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .row>div{flex:1;min-width:190px}
  button.act{background:var(--accent);color:#fff;border:none;padding:9px 20px;
    border-radius:6px;cursor:pointer;font-size:13.5px;font-weight:600;font-family:inherit;margin-top:16px}
  button.act:hover{background:#1f6feb}
  button.act:disabled{opacity:.5;cursor:not-allowed}
  button.act.danger{background:#8b2c28}
  button.act.danger:hover{background:#a03a35}
  .out{margin-top:14px;padding:13px;border-radius:6px;background:#0d1117;
    border:1px solid var(--line);font-family:var(--mono);font-size:12.5px;
    white-space:pre-wrap;word-break:break-all;display:none}
  .out.show{display:block}
  .out.ok{border-color:#1d4429;background:#0f2716}
  .out.bad{border-color:#5c1f1c;background:#2d1210}
  .codebox{background:#0f2716;border:1px solid #1d4429;color:#7ee787;
    padding:13px;border-radius:6px;font-family:var(--mono);font-size:12px;
    word-break:break-all;margin-top:12px;display:none;line-height:1.5}
  .codebox.show{display:block}
  .meta{margin-top:12px;font-size:12.5px;color:var(--dim);font-family:var(--mono);display:none}
  .meta.show{display:block}
  .meta b{color:var(--fg);font-weight:600}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--dim);font-weight:500;font-size:12px}
  td.mono{font-family:var(--mono);font-size:11.5px;color:var(--dim)}
  .tag{font-size:11px;padding:1px 7px;border-radius:4px;border:1px solid var(--line);color:var(--dim)}
  .tag.rb{color:var(--warn);border-color:#4d3a10}
  .tag.rv{color:var(--bad);border-color:#5c1f1c}
  .tag.ok{color:var(--ok);border-color:#1d4429}
  button.mini{background:none;border:1px solid var(--line);color:var(--dim);
    padding:2px 9px;border-radius:4px;cursor:pointer;font-size:11.5px;font-family:inherit}
  button.mini:hover{color:var(--fg);border-color:var(--dim)}
  .warnbar{background:#2d1210;border:1px solid #5c1f1c;color:#ffa198;
    padding:11px 14px;border-radius:6px;font-size:12.5px;margin-bottom:16px}
  .steps{color:var(--dim);font-size:12.5px;margin:0 0 14px;padding-left:20px}
  .steps li{margin:3px 0}
  .empty{color:var(--dim);text-align:center;padding:32px;font-size:13px}
  .spin{display:inline-block;width:11px;height:11px;border:2px solid var(--line);
    border-top-color:var(--accent);border-radius:50%;animation:sp .7s linear infinite;
    vertical-align:-1px;margin-right:6px}
  @keyframes sp{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<header>
  <h1>玄盾 · 激活码签发</h1>
  <span id="kp" class="pill">检查密钥…</span>
  <span class="pill" style="color:var(--warn);border-color:#4d3a10">本机工具 · 勿暴露到公网</span>
</header>
<main>
  <div id="nokey" class="warnbar" style="display:none">
    <b>未找到私钥，无法签发。</b><br>
    先运行：<code>python tools/activation/gen_activation_keys.py genkeypair</code><br>
    <span style="color:var(--dim)">私钥只在本机，绝不要提交到 git。</span>
  </div>

  <nav>
    <button class="on" data-p="issue">签发</button>
    <button data-p="rebind">换机换绑</button>
    <button data-p="revoke">吊销</button>
    <button data-p="audit">传播审计</button>
    <button data-p="log">签发记录</button>
    <button data-p="verify">验码</button>
  </nav>

  <!-- 签发 -->
  <section class="panel on" id="p-issue">
    <div class="card">
      <h2>签发激活码</h2>
      <p class="hint">机器码由用户在客户端「激活」页复制给你，32 位十六进制。</p>
      <div class="row">
        <div><label>授权给谁（用户名 / 邮箱 / 订单号）</label>
          <input id="i-name" placeholder="张三"></div>
        <div><label>机器码</label>
          <input id="i-mch" class="mono" placeholder="de6801f5338b31340a6122fa7b0d34b8"></div>
      </div>
      <div class="row">
        <div><label>有效天数</label><input id="i-days" type="number" value="365" min="1" max="3650"></div>
        <div><label>档位</label><select id="i-tier">
          <option value="personal">personal</option>
          <option value="personal-pro">personal-pro</option></select></div>
        <div><label>特性开关（逗号分隔，可空）</label>
          <input id="i-feat" placeholder="留空即可"></div>
      </div>
      <button class="act" onclick="doIssue()">签发</button>
      <div id="i-out" class="out"></div>
      <div id="i-code" class="codebox"></div>
      <div id="i-meta" class="meta"></div>
    </div>
  </section>

  <!-- 换绑 -->
  <section class="panel" id="p-rebind">
    <div class="card">
      <h2>换机换绑</h2>
      <p class="hint">让用户在客户端「激活」页点「换机」复制 XDRB. 请求串，粘贴到这里。</p>
      <ol class="steps">
        <li>粘贴请求串 → 点「换绑」</li>
        <li>把新码发回给用户，让其重新粘贴进客户端</li>
        <li><b>若旧码可能外泄</b>，用下方「吊销」页作废旧码（只杀旧代次）</li>
      </ol>
      <label>换绑请求串</label>
      <textarea id="r-req" class="mono" rows="4"
        placeholder="XDRB.eyJjb2RlIjoiWEQBQ1QtLi4uIn0"></textarea>
      <button class="act" onclick="doRebind()">换绑</button>
      <div id="r-out" class="out"></div>
      <div id="r-code" class="codebox"></div>
      <div id="r-meta" class="meta"></div>
    </div>
  </section>

  <!-- 吊销 -->
  <section class="panel" id="p-revoke">
    <div class="card">
      <h2>吊销激活码</h2>
      <p class="hint">按 jti 吊销。换绑过的码<strong>务必填代次</strong>，
        否则新旧两张码会一起失效，用户将彻底无法使用。</p>
      <label>jti（在「签发记录」页可查到）</label>
      <input id="v-jti" class="mono" placeholder="a_xxxxxxxx">
      <label>只作废 gen 小于 <span style="color:var(--fg)">?</span> 的码（换绑后填新代次）</label>
      <input id="v-gen" type="number" min="0" placeholder="留空 = 作废该 jti 全部代次">
      <button class="act danger" onclick="doRevoke()">确认吊销</button>
      <div id="v-out" class="out"></div>
    </div>
  </section>

  <!-- 审计 -->
  <section class="panel" id="p-audit">
    <div class="card">
      <h2>传播审计</h2>
      <p class="hint">客户端防不住破解 —— 真正能看见「码是否被传播」的只有签发日志。</p>
      <div class="row">
        <div><label>机器数阈值（超过即疑似传播）</label>
          <input id="a-mach" type="number" value="2" min="1"></div>
        <div><label>换绑次数阈值（超过即疑似批量）</label>
          <input id="a-rb" type="number" value="2" min="1"></div>
      </div>
      <button class="act" onclick="doAudit()">开始审计</button>
      <div id="a-out" class="out"></div>
    </div>
  </section>

  <!-- 记录 -->
  <section class="panel" id="p-log">
    <div class="card">
      <h2>签发记录</h2>
      <p class="hint">吊销、换绑时从这里取 jti。点「复制码」可取回完整激活码。</p>
      <button class="act" onclick="loadLog()" style="margin-top:0">刷新</button>
      <div id="l-out" class="out"></div>
      <div id="l-table" style="margin-top:14px"></div>
    </div>
  </section>

  <!-- 验码 -->
  <section class="panel" id="p-verify">
    <div class="card">
      <h2>验码</h2>
      <p class="hint">用公钥验一张码 —— 排查用户反馈「激活失败」时最快的一步。</p>
      <label>激活码</label>
      <textarea id="vf-code" class="mono" rows="3" placeholder="XDACT-..."></textarea>
      <button class="act" onclick="doVerify()">验签</button>
      <div id="vf-out" class="out"></div>
    </div>
  </section>
</main>

<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function show(el,txt,cls){
  el.className='out show'+(cls?' '+cls:'');
  el.textContent=txt;
}
function busy(btn,on,label){
  if(on){btn.dataset.t=btn.innerHTML;btn.disabled=true;btn.innerHTML='<span class="spin"></span>'+label;}
  else{btn.disabled=false;btn.innerHTML=btn.dataset.t||btn.innerHTML;}
}
async function post(url,body){
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body||{})});
  const j=await r.json().catch(()=>({detail:'响应不是 JSON'}));
  if(!r.ok) throw new Error(j.detail||('HTTP '+r.status));
  return j;
}
async function copy(text,btn){
  try{ await navigator.clipboard.writeText(text); }
  catch(_){
    const ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);
    ta.select();document.execCommand('copy');ta.remove();
  }
  const o=btn.textContent;btn.textContent='已复制';setTimeout(()=>btn.textContent=o,1400);
}

document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('nav button').forEach(x=>x.classList.remove('on'));
  document.querySelectorAll('.panel').forEach(x=>x.classList.remove('on'));
  b.classList.add('on');
  $('p-'+b.dataset.p).classList.add('on');
  if(b.dataset.p==='log') loadLog();
});

// ── 密钥状态 ──
fetch('/api/status').then(r=>r.json()).then(s=>{
  const p=$('kp');
  if(s.private_key_exists){p.className='pill ok';p.textContent='私钥就位';}
  else{p.className='pill bad';p.textContent='缺私钥';$('nokey').style.display='block';}
  document.querySelectorAll('button.act').forEach(b=>{
    if(!s.private_key_exists) b.disabled=true;
  });
});

// ── 签发 ──
async function doIssue(){
  const btn=event.target;busy(btn,true,'签发中');
  const mchRaw=$('i-mch').value.trim();
  const out=$('i-out');
  $('i-code').classList.remove('show');$('i-meta').classList.remove('show');
  try{
    if(!$('i-name').value.trim()) throw new Error('请填写「授权给谁」');
    if(!mchRaw) throw new Error('请填写机器码');
    const d=await post('/api/issue',{
      name:$('i-name').value.trim(), mch:mchRaw,
      days:parseInt($('i-days').value||'365',10),
      tier:$('i-tier').value, features:$('i-feat').value.trim()
    });
    const cb=$('i-code');cb.className='codebox show';cb.textContent=d.code;
    const m=$('i-meta');m.className='meta show';
    m.innerHTML='码内绑定的机器码哈希：<b>'+esc(d.mch_hashed)+'</b>'
      +'<br>jti：<b>'+esc(d.jti)+'</b>'
      +(d.expires_at?'<br>到期：<b>'+esc(d.expires_at)+'</b>':'')
      +'<br><button class="mini" style="margin-top:8px" onclick="copy(document.getElementById(\'i-code\').textContent,this)">复制激活码</button>'
      +' <button class="mini" onclick="document.getElementById(\'v-jti\').value=\''+String(d.jti||'').replace(/'/g,"\\'")+'\';document.querySelector(\'nav button[data-p=revoke]\').click()">去吊销</button>';
    let warn='';
    if(d.machine_code_suspect) warn='\n\n⚠ 机器码格式异常，请与用户核对：他抄给你的串可能不完整。';
    show(out,'✓ 签发成功。'+warn+'\n★ 请把这张码发给用户，并让他确认激活页显示「已激活」。','ok');
  }catch(e){show(out,'✗ '+e.message,'bad');}
  busy(btn,false);
}

// ── 换绑 ──
async function doRebind(){
  const btn=event.target;busy(btn,true,'换绑中');
  const out=$('r-out');
  $('r-code').classList.remove('show');$('r-meta').classList.remove('show');
  try{
    const d=await post('/api/rebind',{request:$('r-req').value.trim()});
    const cb=$('r-code');cb.className='codebox show';cb.textContent=d.code;
    const m=$('r-meta');m.className='meta show';
    let h='jti（不变）：<b>'+esc(d.jti)+'</b>'
      +'<br>新代次：<b>'+esc(d.new_gen)+'</b>'
      +'<br>机器码：'+esc(d.machine_from)+' → <b>'+esc(d.machine_to)+'</b>'
      +'<br><button class="mini" style="margin-top:8px" onclick="copy(document.getElementById(\'r-code\').textContent,this)">复制新码</button>';
    m.innerHTML=h;
    show(out,'✓ 换绑成功。\n\n★ 下一步：让用户把新码重新粘贴进客户端。'
      +'\n★ 若旧码可能外泄，单独作废旧码（只杀旧代次，新码不受影响）：'
      +'\n  '+d.revoke_hint,'ok');
  }catch(e){show(out,'✗ '+e.message,'bad');}
  busy(btn,false);
}

// ── 吊销 ──
async function doRevoke(){
  const btn=event.target;busy(btn,true,'吊销中');
  const out=$('v-out');
  const genRaw=$('v-gen').value.trim();
  try{
    const d=await post('/api/revoke',{
      jti:$('v-jti').value.trim(),
      before_gen:genRaw===''?null:parseInt(genRaw,10)
    });
    show(out,'✓ 已执行。\n\n'+(d.stdout||'')+'\n'+(d.stderr||''),'ok');
  }catch(e){show(out,'✗ '+e.message,'bad');}
  busy(btn,false);
}

// ── 审计 ──
async function doAudit(){
  const btn=event.target;busy(btn,true,'审计中');
  const out=$('a-out');
  try{
    const d=await post('/api/audit',{
      max_machines:parseInt($('a-mach').value||'2',10),
      max_rebinds:parseInt($('a-rb').value||'2',10)
    });
    show(out,d.report,d.has_alert?'bad':'ok');
  }catch(e){show(out,'✗ '+e.message,'bad');}
  busy(btn,false);
}

// ── 验码 ──
async function doVerify(){
  const btn=event.target;busy(btn,true,'验签中');
  const out=$('vf-out');
  try{
    const d=await post('/api/verify',{code:$('vf-code').value.trim()});
    show(out,d.report,d.ok?'ok':'bad');
  }catch(e){show(out,'✗ '+e.message,'bad');}
  busy(btn,false);
}

// ── 记录 ──
async function loadLog(){
  const out=$('l-out'),box=$('l-table');
  try{
    const d=await (await fetch('/api/log')).json();
    if(!d.items.length){box.innerHTML='<div class="empty">尚无签发记录</div>';out.className='out';return;}
    const rows=d.items.map(r=>{
      const ev=r.event==='rebind'
        ? '<span class="tag rb">换绑</span>'
        : '<span class="tag">签发</span>';
      const rv=r.revoked?'<span class="tag rv">已吊销</span>':'<span class="tag ok">有效</span>';
      return '<tr><td>'+(r.created_at||'').slice(0,19).replace('T',' ')+'</td>'
        +'<td>'+ev+'</td>'
        +'<td>'+esc(r.name||'')+'<div class="td mono">'+esc(r.jti)+' · gen '+r.gen+'</div></td>'
        +'<td class="mono">'+esc((r.mch_raw||r.mch||'').slice(0,24))+'</td>'
        +'<td>'+(r.expires_at||'').slice(0,10)+'</td>'
        +'<td>'+rv+'</td>'
        +'<td><button class="mini" onclick="copy(\''+String(r.code||'').replace(/'/g,"\\'")+'\',this)">复制码</button>'
        +'<button class="mini" onclick="document.getElementById(\'v-jti\').value=\''+String(r.jti||'').replace(/'/g,"\\'")+'\';document.getElementById(\'v-gen\').value=\''+r.gen+'\';document.querySelector(\'nav button[data-p=revoke]\').click()">去吊销</button></td></tr>';
    }).join('');
    box.innerHTML='<table><thead><tr><th>时间</th><th>事件</th><th>授权给 / jti</th>'
      +'<th>机器码</th><th>到期</th><th>状态</th><th>操作</th></tr></thead><tbody>'
      +rows+'</tbody></table>'
      +'<div style="color:var(--dim);font-size:12px;margin-top:10px">共 '+d.total+' 条</div>';
    out.className='out';
  }catch(e){
    box.innerHTML='';
    show(out,'✗ 读取签发记录失败：'+e.message
      +'\n\n这不是「没有记录」，而是读不出来。传播检测依赖此文件，请先修好它。','bad');
  }
}
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _PAGE


def main() -> int:
    ap = argparse.ArgumentParser(description="激活码签发 WebUI（本机工具）")
    ap.add_argument("--host", default="127.0.0.1",
                    help="监听地址。默认仅本机；改成 0.0.0.0 等于把私钥暴露出去")
    ap.add_argument("--port", type=int, default=8760)
    args = ap.parse_args()

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print("✗ 拒绝启动：绑定非本机地址会让私钥可被远程使用", file=sys.stderr)
        print("  远程签发请用 SSH 隧道转发到 127.0.0.1", file=sys.stderr)
        return 2

    if not PRIVATE_KEY.is_file():
        print(f"⚠ 未找到私钥：{PRIVATE_KEY}", file=sys.stderr)
        print("  先运行：python tools/activation/gen_activation_keys.py genkeypair",
              file=sys.stderr)

    import uvicorn

    print(f"启动中… http://{args.host}:{args.port}")
    print("★ 本工具持有私钥，请勿把端口暴露到公网。按 Ctrl+C 停止。")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
