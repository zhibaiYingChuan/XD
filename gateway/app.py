"""
玄盾企业级安全网关 — FastAPI 服务入口

端点:
  /health             健康检查（三态）
  /metrics            Prometheus 指标
  /api/v1/protect     安全检测（含路由）
  /api/v1/models      模型列表
  /api/v1/stats       实时统计
  /api/v1/status      集群状态（Redis/PostgreSQL）
  /api/config/reload  配置热加载
"""
import os, sys, time, json, logging, traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from daoti_xuandun import XuanDun, XuanDunConfig, DefenseLevel, ProtectResult
from daoti_xuandun import __version__ as ENGINE_VERSION
from daoti_xuandun.integrations import (
    AlertManager, AlertEvent,
    DingTalkNotifier, FeishuNotifier, EmailNotifier, WebhookNotifier, SyslogNotifier,
)
from daoti_xuandun.tools.config_snapshot import create_snapshot, list_snapshots, restore_snapshot
from .jwt_auth import ApiKeyVerifier
from .revoked_store import RevokedStore

# ── 版本号：从 daoti_xuandun SSOT 读取，不硬编码 ──
VERSION = ENGINE_VERSION

# ── API Key 认证 ──
# 管理密钥（主密钥）：从环境变量读取，逗号分隔支持多个；XUANDUN_ADMIN_KEY 优先，
# 兼容旧变量 XUANDUN_API_KEY，供管理控制台/内部运维登录管理端点。
# 企业 API Key：由供应商用私钥离线签发的 RS256 JWT（XDKEY-<jwt>），网关用公钥离线验签，
# 携带套餐(tier)与有效期(exp)，用于业务端点鉴权与计量收费。
_ADMIN_KEYS = set(
    k.strip() for k in (
        os.getenv("XUANDUN_ADMIN_KEY") or os.getenv("XUANDUN_API_KEY") or ""
    ).split(",") if k.strip()
)
_jwt = ApiKeyVerifier()          # 企业 API Key 离线验签
_revoked = RevokedStore()        # 已吊销 jti 黑名单

# 公开路径：无需认证
_PUBLIC_PATHS = {"/health", "/metrics", "/", "/docs", "/openapi.json", "/favicon.ico"}
# 业务路径：企业 API Key（JWT）可访问；其余非公开路径均为管理路径，仅管理密钥可访问
_BUSINESS_PATHS = {"/api/v1/protect"}

class APIKeyMiddleware(BaseHTTPMiddleware):
    """企业密钥鉴权中间件：管理密钥(env) + 企业 API Key(JWT)，管理端点 fail-closed。"""
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in _PUBLIC_PATHS or path.startswith("/docs") or path.startswith("/openapi"):
            return await call_next(request)

        api_key = request.headers.get("X-API-Key", "")
        is_business_route = path in _BUSINESS_PATHS

        # 管理端点 fail-closed：未配置管理密钥时拒绝访问并给出引导
        if not _ADMIN_KEYS and not is_business_route:
            return JSONResponse(status_code=503, content={
                "detail": "网关未配置管理员密钥。请设置环境变量 XUANDUN_ADMIN_KEY 后重启网关。"})

        # 管理密钥（环境变量主密钥）：全量放行
        if api_key and api_key in _ADMIN_KEYS:
            return await call_next(request)

        # 企业 API Key（JWT）：仅业务端点可用
        if is_business_route:
            if not _jwt.is_configured():
                return JSONResponse(status_code=503, content={
                    "detail": "网关未配置企业密钥公钥。请设置 XUANDUN_PUBLIC_KEY 或 XUANDUN_PUBLIC_KEY_PATH。"})
            claims = _jwt.verify(api_key, revoked_jtis=frozenset(_revoked.list()))
            if claims is None:
                return JSONResponse(status_code=401, content={
                    "detail": "Unauthorized: 无效、过期或已吊销的 API Key"})
            request.state.api_key_claims = claims
            return await call_next(request)

        # 非业务路径且非管理密钥：拒绝
        return JSONResponse(status_code=401, content={"detail": "Unauthorized: 需要管理密钥"})

from .config import load_config, XuanDunGatewayConfig
from .router import ModelRouter
from .state_store import RedisStateStore, RedisConfig
from .audit_store import AuditLogStore, AuditLogConfig

# ── 日志 ──

class JsonFormatter(logging.Formatter):
    def format(self, record):
        e = {"timestamp": datetime.now(timezone.utc).isoformat(), "level": record.levelname,
             "logger": record.name, "message": record.getMessage(),
             "module": record.module, "function": record.funcName}
        for f in ("session_id", "event"):
            if hasattr(record, f): e[f] = getattr(record, f)
        if record.exc_info and record.exc_info[1]:
            e["error"] = str(record.exc_info[1])
            e["traceback"] = traceback.format_exc()
        return json.dumps(e, ensure_ascii=False)

class AuditLogger(logging.LoggerAdapter):
    def __init__(self, logger, extra=None):
        super().__init__(logger, extra or {})
    def audit(self, event: str, **kwargs):
        extra = dict(self.extra); extra["event"] = event
        for k, v in kwargs.items(): extra[k] = v
        self.logger.info(f"[AUDIT] {event}", extra=extra)

def setup_logging(level="info"):
    root = logging.getLogger("xuandun")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    h = logging.StreamHandler(sys.stdout); h.setFormatter(JsonFormatter())
    root.handlers.clear(); root.addHandler(h)
    # ── 日志轮转：生产环境写入文件，10MB×3个文件 ──
    log_dir = os.getenv("XUANDUN_LOG_DIR")
    if log_dir:
        log_dir_source = "环境变量 XUANDUN_LOG_DIR"
    else:
        log_dir = os.path.join(os.path.dirname(__file__), "..", "logs")
        log_dir_source = "默认路径（建议生产环境设置 XUANDUN_LOG_DIR）"
    try:
        from logging.handlers import RotatingFileHandler
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "xuandun.log")
        fh = RotatingFileHandler(
            log_path,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=3,
            encoding="utf-8",
        )
        fh.setFormatter(JsonFormatter())
        root.addHandler(fh)
        # 启动时告知运维日志落盘位置（不可变思维：路径可审计）
        root.info("日志轮转就绪", extra={"event": "log_setup", "log_dir": log_dir,
                   "source": log_dir_source, "max_mb": 10, "backups": 3})
    except Exception as e:
        root.warning("日志文件不可用，仅输出stdout", extra={"event": "log_setup_failed",
                     "log_dir": log_dir, "error": str(e)})
    return root

# ── 指标 ──

class MetricsRegistry:
    def __init__(self):
        self.start_time = time.time()
        self.requests_total = self.blocks_total = self.passes_total = self.errors_total = 0
        self.proxy_requests = self.proxy_blocks = 0
        self.manual_requests = self.manual_blocks = 0
        self.latencies_ms = []; self._max_samples = 10000

    def record_request(self, blocked, latency_ms, source="proxy"):
        self.requests_total += 1
        if blocked: self.blocks_total += 1
        else: self.passes_total += 1
        # 分来源统计
        if source == "proxy":
            self.proxy_requests += 1
            if blocked: self.proxy_blocks += 1
        else:
            self.manual_requests += 1
            if blocked: self.manual_blocks += 1
        self.latencies_ms.append(latency_ms)
        if len(self.latencies_ms) > self._max_samples:
            self.latencies_ms = self.latencies_ms[-self._max_samples:]

    def record_error(self): self.errors_total += 1

    def _pct(self, p):
        if not self.latencies_ms: return 0.0
        s = sorted(self.latencies_ms)
        return s[min(int(len(s) * p), len(s) - 1)]

    @property
    def p50(self): return self._pct(0.50)
    @property
    def p95(self): return self._pct(0.95)
    @property
    def rate(self): return self.blocks_total / max(self.requests_total, 1) * 100
    @property
    def uptime(self): return time.time() - self.start_time

    def render(self):
        return "\n".join([
            "# HELP xuandun_requests_total Total protection requests",
            f"# TYPE xuandun_requests_total counter\nxuandun_requests_total {self.requests_total}\n",
            "# HELP xuandun_blocks_total Total blocked requests",
            f"# TYPE xuandun_blocks_total counter\nxuandun_blocks_total {self.blocks_total}\n",
            "# HELP xuandun_passes_total Total passed requests",
            f"# TYPE xuandun_passes_total counter\nxuandun_passes_total {self.passes_total}\n",
            "# HELP xuandun_errors_total Total processing errors",
            f"# TYPE xuandun_errors_total counter\nxuandun_errors_total {self.errors_total}\n",
            "# HELP xuandun_block_rate Current block rate (%)",
            f"# TYPE xuandun_block_rate gauge\nxuandun_block_rate {self.rate:.2f}\n",
            "# HELP xuandun_latency_p50_ms P50 latency (ms)",
            f"# TYPE xuandun_latency_p50_ms gauge\nxuandun_latency_p50_ms {self.p50:.2f}\n",
            "# HELP xuandun_latency_p95_ms P95 latency (ms)",
            f"# TYPE xuandun_latency_p95_ms gauge\nxuandun_latency_p95_ms {self.p95:.2f}\n",
            "# HELP xuandun_uptime_seconds Gateway uptime (s)",
            f"# TYPE xuandun_uptime_seconds gauge\nxuandun_uptime_seconds {self.uptime:.1f}\n",
        ])

# ── 全局状态 ──

metrics = MetricsRegistry()

# ── 企业 API Key 计量 ──
# 企业 API Key 由供应商（玄盾）离线签发（RS256 JWT），网关只负责验签与计量，
# 无法自建。首次产生流量时按 jti 记录元数据，后续递增用量计数（存于 state_store）。
_KEY_META_PREFIX = "ent_meta:"      # state_store session 命名空间中的元数据 key 前缀
_KEY_USAGE_PREFIX = "usage:"        # 计量计数器前缀

def _record_key_usage(claims: dict) -> None:
    """记录一次企业密钥调用：首次写入元数据，随后递增用量计数。"""
    if not state_store:
        return
    jti = claims.get("jti")
    if not jti:
        return
    if state_store.get_session(_KEY_META_PREFIX + jti) is None:
        state_store.store_session(_KEY_META_PREFIX + jti, {
            "jti": jti,
            "sub": claims.get("sub", ""),
            "tier": claims.get("tier", ""),
            "quota": claims.get("quota", 0),
            "exp": claims.get("exp", 0),
            "iss": claims.get("iss", ""),
        })
    state_store.incr_counter(_KEY_USAGE_PREFIX + jti, 1)
shield: Optional[XuanDun] = None
gateway_config: Optional[XuanDunGatewayConfig] = None
model_router: Optional[ModelRouter] = None
state_store: Optional[RedisStateStore] = None
audit_store: Optional[AuditLogStore] = None
logger: Optional[logging.Logger] = None
audit: Optional[AuditLogger] = None
_hstatus, _hmsg = "degraded", "Engine initializing..."
_etime: float = 0.0
_router_cfg_path: Optional[str] = None   # 多模型路由配置文件路径（保存模型配置用）

# ── 告警通道：AlertManager 实例 + 通知通道类映射（供 Web 管理端配置） ──
alert_manager: Optional[AlertManager] = None
_NOTIFIER_CLASSES = {
    "dingtalk": DingTalkNotifier,
    "feishu": FeishuNotifier,
    "email": EmailNotifier,
    "webhook": WebhookNotifier,
    "syslog": SyslogNotifier,
}

def get_health():
    if shield is None: return ("degraded", "Engine not loaded")
    if metrics.requests_total > 10 and metrics.errors_total / max(metrics.requests_total, 1) > 0.5:
        return ("degraded", f"High error rate: {metrics.errors_total}/{metrics.requests_total}")
    return (_hstatus, _hmsg)

# ── 模型 ──

class ProtectReq(BaseModel):
    text: str = Field(..., min_length=1, max_length=100000)
    session_id: Optional[str] = None
    model_id: Optional[str] = None
    direction: str = Field("input", pattern="^(input|output)$")  # 检测方向：input=输入护栏，output=模型输出护栏
    source: str = Field("proxy", pattern="^(proxy|manual|batch)$")  # 检测来源：proxy=实时流量, manual=手动检测, batch=批量检测

class ProtectResp(BaseModel):
    allowed: bool; reason: Optional[str] = None
    reject_stage: Optional[str] = None; latency_ms: float

class HealthResp(BaseModel):
    status: str; message: str; version: str
    uptime_seconds: float; engine_ready: bool; metrics_snapshot: Dict = {}

# ── 生命周期 ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    global shield, gateway_config, model_router, state_store, audit_store, logger, audit
    global _hstatus, _hmsg, _etime, _router_cfg_path, alert_manager

    config_path = os.getenv("XUANDUN_CONFIG_PATH", None)
    gateway_config = load_config(config_path)
    logger = setup_logging(gateway_config.gateway.log_level)
    audit = AuditLogger(logger)

    redis_enabled = os.getenv("XUANDUN_REDIS_ENABLED", "0") == "1"
    state_store = RedisStateStore(RedisConfig(
        url=os.getenv("XUANDUN_REDIS_URL", "redis://localhost:6379/0"),
        enabled=redis_enabled))

    pg_enabled = os.getenv("XUANDUN_PG_ENABLED", "0") == "1"
    audit_store = AuditLogStore(AuditLogConfig(
        dsn=os.getenv("XUANDUN_PG_DSN", "postgresql://localhost:5432/xuandun"),
        enabled=pg_enabled))
    if pg_enabled: await audit_store.init_async()

    logger.info("网关启动中...", extra={"event": "gateway_startup",
                "redis": state_store.get_status(), "postgres": audit_store.get_status()})

    # 初始化告警管理器（空实例，通道由 Web 管理端配置）
    alert_manager = AlertManager()

    try:
        t0 = time.time()
        dl = getattr(DefenseLevel, gateway_config.security.defense_level.upper(), DefenseLevel.STANDARD)
        ec = XuanDunConfig.preset(dl)
        ec.enable_observing_mode = (gateway_config.security.mode == "observing")
        shield = XuanDun(config=ec)
        _etime = time.time() - t0
        bi = getattr(shield.domain_awareness, "_bilateral_available", False)
        _hstatus, _hmsg = "ok", f"Engine in {_etime:.2f}s, bilateral={'yes' if bi else 'no'}"

        from daoti_xuandun import __version__ as ev
        logger.info("引擎就绪", extra={"event": "engine_ready", "load_s": _etime, "bilateral": bi, "version": ev})

        rc = os.getenv("XUANDUN_ROUTER_CONFIG", os.path.join(os.path.dirname(__file__), "config.yaml"))
        _router_cfg_path = rc
        model_router = ModelRouter(rc)
        logger.info("路由就绪", extra={"event": "router_ready", "models": model_router.get_stats()["model_count"]})

    except Exception as e:
        _hstatus, _hmsg = "unhealthy", f"Engine failed: {e}"
        logger.error("引擎加载失败", extra={"event": "engine_error", "error": str(e)}, exc_info=True)

    yield

    if audit_store: await audit_store.flush()
    if audit_store: await audit_store.close()
    if state_store: state_store.close()
    logger.info("网关关闭", extra={"event": "gateway_shutdown"})


app = FastAPI(title="玄盾 AI安全网关", description="企业级 LLM 运行时安全防护网关",
              version=VERSION, lifespan=lifespan)
app.add_middleware(APIKeyMiddleware)

# ── 安全响应头中间件 ──
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ── CORS 中间件（限制来源） ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)

@app.get("/health", response_model=HealthResp)
async def health_check():
    s, m = get_health()
    return HealthResp(status=s, message=m, version=VERSION,
        uptime_seconds=metrics.uptime, engine_ready=shield is not None,
        metrics_snapshot={"requests_total": metrics.requests_total, "blocks_total": metrics.blocks_total,
                          "errors_total": metrics.errors_total,
                          "p50_ms": round(metrics.p50, 2), "p95_ms": round(metrics.p95, 2)})

@app.get("/metrics")
async def prometheus_metrics():
    return PlainTextResponse(content=metrics.render())

@app.post("/api/v1/protect", response_model=ProtectResp)
async def protect_input(request: ProtectReq, req: Request):
    if shield is None:
        metrics.record_error()
        raise HTTPException(status_code=503, detail="Security engine not ready")
    t0 = time.time()
    sid = request.session_id or "anonymous"
    xmid = req.headers.get("X-Model-ID")
    # 企业密钥计量：按 jti 记录用量（管理密钥/未配置时无 claims，自动跳过）
    claims = getattr(req.state, "api_key_claims", None)
    if claims:
        _record_key_usage(claims)
    rt = model_router.resolve(x_model_id=xmid,
        request_body={"model": request.model_id} if request.model_id else None) if model_router else None

    try:
        # 输出护栏检测：direction=output 时走引擎输出侧护栏（check_output），
        # 否则走默认输入护栏（protect）。修复"模型输出护栏检测文本一直放行"问题。
        if request.direction == "output":
            out = shield.check_output(request.text, session_id=sid)
            result = ProtectResult(allowed=bool(out.get("allowed", True)))
            result.reason = out.get("reason")
            result.reject_stage = (
                f"output_guardrail:{out.get('risk_level', 'unknown')}"
                if out.get("action") in ("block", "redact", "alert") and not out.get("allowed", True)
                else None
            )
        else:
            result = shield.protect(request.text)
        ms = (time.time() - t0) * 1000
        blocked = not result.allowed
        metrics.record_request(blocked=blocked, latency_ms=ms, source=request.source)

        if state_store:
            state_store.incr_counter("requests_total")
            if blocked: state_store.incr_counter("blocks_total")

        audit.audit("protect_request", session_id=sid, text_preview=request.text[:100],
                    allowed=result.allowed, reason=getattr(result, "reason", None),
                    stage=getattr(result, "reject_stage", None), latency_ms=round(ms, 2),
                    client_ip=req.client.host if req.client else "unknown",
                    model_id=request.model_id, routed_to=rt.id if rt else None)

        if audit_store:
            audit_store.record("protect_request", session_id=sid, text_preview=request.text[:100],
                               allowed=result.allowed, reason=getattr(result, "reason", None),
                               stage=getattr(result, "reject_stage", None), latency_ms=ms,
                               client_ip=req.client.host if req.client else "unknown",
                               model_id=request.model_id, routed_to=rt.id if rt else None)
            await audit_store.flush()

        return ProtectResp(allowed=result.allowed, reason=getattr(result, "reason", None),
                           reject_stage=getattr(result, "reject_stage", None), latency_ms=round(ms, 2))

    except Exception as e:
        metrics.record_error()
        # 限流异常返回 429，其他异常返回 500
        err_name = type(e).__name__
        if err_name == "RateLimitError" or "quota" in str(e).lower() or "limit" in str(e).lower():
            raise HTTPException(status_code=429, detail=str(e))
        logger.error("检测异常", extra={"event": "protect_error", "error": str(e)}, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Detection error: {str(e)}")

@app.get("/api/v1/stats")
async def get_stats():
    # 仪表盘只显示 proxy（实时流量）数据，manual 数据独立呈现
    proxy_rate = (metrics.proxy_blocks / max(metrics.proxy_requests, 1) * 100) if metrics.proxy_requests > 0 else 0.0
    return {"requests_total": metrics.proxy_requests, "blocks_total": metrics.proxy_blocks,
            "passes_total": metrics.proxy_requests - metrics.proxy_blocks,
            "errors_total": metrics.errors_total,
            "block_rate": round(proxy_rate, 2),
            "p50_latency_ms": round(metrics.p50, 2),
            "p95_latency_ms": round(metrics.p95, 2), "uptime_seconds": metrics.uptime,
            "engine_version": VERSION, "engine_ready": shield is not None,
            "redis": state_store.get_status() if state_store else {},
            "audit_log": audit_store.get_status() if audit_store else {},
            # 手动检测数据（独立呈现，不计入仪表盘主指标）
            "manual_requests": metrics.manual_requests,
            "manual_blocks": metrics.manual_blocks}

@app.post("/api/v1/report")
async def export_report(request: Request):
    """安全报告导出 — 基于内存 metrics 生成 CSV/JSON/HTML/MD 报告。

    请求体: { "start_date": "2026-08-01", "end_date": "2026-08-14",
              "format": "csv|json|html|md", "sections": ["summary","trend","distribution"] }
    返回: { "file_path": "...", "file_size": ..., "format": "...", "summary": {...} }
    """
    import os, tempfile, csv, io
    from datetime import datetime, date
    body = await request.json()
    start_date = body.get("start_date", "")
    end_date = body.get("end_date", "")
    fmt = body.get("format", "html")
    sections = body.get("sections", ["summary"])

    # 基于 metrics 构建摘要数据（只含 proxy 数据）
    proxy_rate = (metrics.proxy_blocks / max(metrics.proxy_requests, 1) * 100) if metrics.proxy_requests > 0 else 0.0
    summary = {
        "total_requests": metrics.proxy_requests,
        "total_blocked": metrics.proxy_blocks,
        "block_rate": round(proxy_rate, 2),
        "avg_daily": round(metrics.proxy_requests / max(1, metrics.uptime / 86400)) if metrics.uptime > 0 else 0,
        "period": {"start": start_date, "end": end_date},
        "generated_at": datetime.utcnow().isoformat(),
        "manual_requests": metrics.manual_requests,
        "manual_blocks": metrics.manual_blocks,
        "p50_latency_ms": round(metrics.p50, 2),
        "p95_latency_ms": round(metrics.p95, 2),
        "uptime_seconds": round(metrics.uptime, 0),
    }

    # 生成文件
    if fmt == "json":
        fd, file_path = tempfile.mkstemp(suffix=".json", prefix="xuandun_report_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
    elif fmt == "csv":
        fd, file_path = tempfile.mkstemp(suffix=".csv", prefix="xuandun_report_")
        with os.fdopen(fd, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(["指标", "值"])
            w.writerow(["检测总数", summary["total_requests"]])
            w.writerow(["拦截次数", summary["total_blocked"]])
            w.writerow(["拦截率(%)", summary["block_rate"]])
            w.writerow(["P50延迟(ms)", summary["p50_latency_ms"]])
            w.writerow(["P95延迟(ms)", summary["p95_latency_ms"]])
            w.writerow(["手动检测总数", summary["manual_requests"]])
            w.writerow(["手动拦截数", summary["manual_blocks"]])
            w.writerow(["运行时间(s)", summary["uptime_seconds"]])
    elif fmt == "md":
        fd, file_path = tempfile.mkstemp(suffix=".md", prefix="xuandun_report_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"# 玄盾安全报告\n\n")
            f.write(f"**报告周期**: {start_date} ~ {end_date}\n\n")
            f.write(f"## 概览\n\n")
            f.write(f"| 指标 | 值 |\n|------|----|\n")
            f.write(f"| 检测总数 | {summary['total_requests']} |\n")
            f.write(f"| 拦截次数 | {summary['total_blocked']} |\n")
            f.write(f"| 拦截率 | {summary['block_rate']}% |\n")
            f.write(f"| P50延迟 | {summary['p50_latency_ms']}ms |\n")
            f.write(f"| P95延迟 | {summary['p95_latency_ms']}ms |\n\n")
            f.write(f"## 手动检测\n\n")
            f.write(f"| 指标 | 值 |\n|------|----|\n")
            f.write(f"| 手动检测总数 | {summary['manual_requests']} |\n")
            f.write(f"| 手动拦截数 | {summary['manual_blocks']} |\n")
    else:
        fd, file_path = tempfile.mkstemp(suffix=".html", prefix="xuandun_report_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"<html><head><meta charset='utf-8'><title>玄盾安全报告</title></head><body>")
            f.write(f"<h1>玄盾安全报告</h1><p>报告周期: {start_date} ~ {end_date}</p>")
            f.write(f"<h2>概览</h2><table border='1' cellpadding='8'>")
            for k, v in [("检测总数", summary["total_requests"]), ("拦截次数", summary["total_blocked"]),
                         ("拦截率", f"{summary['block_rate']}%"), ("P50延迟", f"{summary['p50_latency_ms']}ms"),
                         ("P95延迟", f"{summary['p95_latency_ms']}ms")]:
                f.write(f"<tr><td>{k}</td><td>{v}</td></tr>")
            f.write(f"</table><h2>手动检测</h2><table border='1' cellpadding='8'>")
            f.write(f"<tr><td>手动检测总数</td><td>{summary['manual_requests']}</td></tr>")
            f.write(f"<tr><td>手动拦截数</td><td>{summary['manual_blocks']}</td></tr>")
            f.write(f"</table></body></html>")

    file_size = os.path.getsize(file_path)
    return {"file_path": file_path, "file_size": file_size, "format": fmt, "summary": summary}

@app.get("/api/v1/status")
async def cluster_status():
    return {
        "engine": VERSION, "engine_ready": shield is not None,
        "redis": state_store.get_status() if state_store else {"backend": "none"},
        "postgres": audit_store.get_status() if audit_store else {"backend": "none"},
        "router": model_router.get_stats() if model_router else {"model_count": 0},
        "global_counters": state_store.get_all_counters() if state_store else {},
    }

@app.post("/api/config/reload")
async def reload_config():
    if model_router is None:
        raise HTTPException(status_code=503, detail="Router not initialized")
    r = model_router.reload()
    logger.info("配置热加载", extra={"event": "config_reload", "models": r["current_models"]})
    return r

@app.get("/api/v1/models")
async def list_models():
    if model_router is None:
        raise HTTPException(status_code=503, detail="Router not initialized")
    s = model_router.get_stats()
    md = {}
    for mid, route in model_router._config.models.items():
        md[mid] = {"name": route.name, "endpoint": route.endpoint,
                   "type": route.type, "weight": route.weight}
    return {**s, "models": md}


# ── 模型配置交互式保存（供 Web 管理端「+ 添加模型」表单写入 config.yaml 并热加载） ──
class ModelItem(BaseModel):
    """单个模型配置项（对应 config.yaml 中 models 列表元素）"""
    id: str
    name: str = ""
    endpoint: str = ""
    type: str = "public"       # public / private
    api_key: str = ""
    weight: float = 100.0


class RoutingReq(BaseModel):
    """路由策略配置（对应 config.yaml 中 routing 节点）"""
    strategy: str = "weighted"  # weighted / round_robin / first_match
    default: str = ""


class ModelsSaveReq(BaseModel):
    """模型配置保存请求体：完整替换 models + routing，保留其他顶层键（gateway/security/config）"""
    models: List[ModelItem] = []
    routing: RoutingReq = RoutingReq()


@app.post("/api/config/models")
async def save_models(req: ModelsSaveReq):
    """保存多模型路由配置到 config.yaml 并立即热加载生效。"""
    if model_router is None:
        raise HTTPException(status_code=503, detail="Router not initialized")
    path = _router_cfg_path
    if not path:
        raise HTTPException(status_code=500, detail="Router config path not set")

    # 输入校验（交互式表单的兜底，防止写入非法配置）
    ids = [m.id.strip() for m in req.models]
    if any(not x for x in ids):
        raise HTTPException(status_code=400, detail="模型 ID 不能为空")
    if len(set(ids)) != len(ids):
        raise HTTPException(status_code=400, detail="模型 ID 不能重复")
    for m in req.models:
        if not m.endpoint.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail=f"模型 {m.id} 的 endpoint 必须以 http:// 或 https:// 开头")
    if req.routing.default and req.routing.default not in ids:
        raise HTTPException(status_code=400, detail=f"默认模型 {req.routing.default} 不在已配置模型中")

    # 读取现有 YAML，仅替换 models/routing，保留 gateway/security/config 等其他顶层键
    data = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

    # 已配置密钥按 id 索引：前端 list_models 不返回 api_key，表单留空表示"保持不变"，
    # 此处对空 api_key 的模型回填既有密钥，避免交互式保存误清空密钥
    existing_keys = {}
    if model_router._config:
        for mid, route in model_router._config.models.items():
            existing_keys[mid] = route.api_key

    models_out = []
    for m in req.models:
        key = m.api_key
        if not key and existing_keys.get(m.id.strip()):
            key = existing_keys[m.id.strip()]
        models_out.append(
            {"id": m.id.strip(), "name": m.name, "endpoint": m.endpoint, "type": m.type,
             "api_key": key, "weight": m.weight}
        )
    data["models"] = models_out
    data["routing"] = {"strategy": req.routing.strategy, "default": req.routing.default}

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
    os.replace(tmp, path)

    r = model_router.reload()
    logger.info("模型配置已保存", extra={"event": "models_saved", "models": r["current_models"]})
    return {**r, "routing": {"strategy": req.routing.strategy, "default": req.routing.default}}

# 模式切换乐观锁版本号（防止并发冲突）
_mode_version: int = 1

@app.get("/api/v1/mode")
async def get_mode():
    """获取当前防护模式"""
    global _mode_version
    if shield is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    da = getattr(shield, "domain_awareness", None)
    current_mode = da.mode if da else "protecting"
    return {"mode": current_mode, "version": _mode_version,
            "available": ["protecting", "observing", "blocking"]}

class ModeSwitchReq(BaseModel):
    mode: str = Field(..., pattern="^(protecting|observing|blocking)$")
    version: Optional[int] = None  # 乐观锁版本号，不匹配则拒绝

@app.post("/api/v1/mode")
async def switch_mode(request: ModeSwitchReq):
    """切换防护模式（乐观锁防并发冲突）"""
    global _mode_version
    if shield is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    # 乐观锁：版本号不匹配说明有并发修改，拒绝本次请求
    if request.version is not None and request.version != _mode_version:
        raise HTTPException(status_code=409,
            detail=f"并发冲突：当前版本 {_mode_version}，你的版本 {request.version}，请刷新后重试")
    da = getattr(shield, "domain_awareness", None)
    if da is None:
        raise HTTPException(status_code=503, detail="Domain awareness not available")
    old_mode = da.mode
    da.mode = request.mode
    _mode_version += 1
    # ── 模式持久化：写入文件，重启后恢复 ──
    try:
        import json
        mode_file = os.path.join(os.path.dirname(__file__), ".xuandun_mode")
        with open(mode_file, "w") as f:
            json.dump({"mode": request.mode, "version": _mode_version}, f)
    except Exception:
        pass  # 写入失败不影响模式切换
    logger.info("防护模式切换", extra={"event": "mode_switch", "from": old_mode, "to": request.mode, "version": _mode_version})
    audit.audit("mode_switch", from_mode=old_mode, to_mode=request.mode)
    return {"mode": request.mode, "previous": old_mode, "version": _mode_version,
            "message": f"模式已从 {old_mode} 切换至 {request.mode}"}

@app.get("/api/v1/audit")
async def query_audit(session_id: Optional[str] = None, event: Optional[str] = None,
                      limit: int = 100, offset: int = 0):
    """查询审计日志（需要 PostgreSQL 启用）"""
    if audit_store is None:
        raise HTTPException(status_code=503, detail="Audit store not initialized")
    status = audit_store.get_status()
    if not status.get("connected"):
        # 未连接 PostgreSQL 时，返回内存缓冲区中的真实检测记录
        records = audit_store.query_memory(limit=limit, offset=offset)
        return {
            "connected": False,
            "memory_mode": True,
            "message": "PostgreSQL 未连接，返回内存缓存中的检测记录。启用方式: XUANDUN_PG_ENABLED=1",
            "records": records,
            "total": len(records),
            "limit": limit,
            "offset": offset,
        }
    records = await audit_store.query(session_id=session_id, event=event, limit=limit, offset=offset)
    return {"connected": True, "records": records, "total": len(records), "limit": limit, "offset": offset}

@app.get("/api/v1/audit/verify")
async def verify_audit_chain():
    """验证审计链 SHA256 哈希完整性"""
    if audit_store is None:
        raise HTTPException(status_code=503, detail="Audit store not initialized")
    result = await audit_store.verify_chain()
    return result

# ── 紧急逃生通道 ──
@dataclass
class EmergencyState:
    enabled: bool = False
    activated_at: Optional[float] = None
    reason: str = ""

_emergency = EmergencyState()

@app.get("/api/v1/emergency")
async def emergency_status():
    """查询紧急逃生通道状态"""
    return {"enabled": _emergency.enabled, "activated_at": _emergency.activated_at,
            "reason": _emergency.reason}

class EmergencyReq(BaseModel):
    enabled: bool = Field(...)
    reason: str = Field(default="", max_length=200)

@app.post("/api/v1/emergency")
async def emergency_toggle(request: EmergencyReq):
    """紧急逃生通道：启用后放行所有请求（绕过检测），用于引擎异常时的紧急止损"""
    global _emergency
    if shield is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    da = getattr(shield, "domain_awareness", None)
    if da is None:
        raise HTTPException(status_code=503, detail="Domain awareness not available")
    da.set_emergency_bypass(request.enabled)
    _emergency.enabled = request.enabled
    _emergency.activated_at = time.time() if request.enabled else None
    _emergency.reason = request.reason if request.enabled else ""
    action = "启用" if request.enabled else "关闭"
    logger.warning("紧急逃生通道", extra={"event": "emergency_toggle", "action": action, "reason": request.reason})
    audit.audit("emergency_toggle", action=action, reason=request.reason)
    return {"enabled": request.enabled, "message": f"逃生通道已{action}" + (f"（原因: {request.reason}）" if request.reason else "")}

# ── 灰度部署比例（Web 管理端滑块） ──
class GrayReq(BaseModel):
    ratio: float = Field(..., ge=0.0, le=1.0)

@app.get("/api/v1/gray")
async def get_gray_ratio():
    """返回当前灰度部署比例（0.0~1.0）。"""
    if shield is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    return {"ratio": shield.get_gray_deploy_ratio()}

@app.post("/api/v1/gray")
async def set_gray_ratio(request: GrayReq):
    """设置灰度部署比例（运行时生效）。"""
    if shield is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    r = shield.set_gray_deploy_ratio(request.ratio)
    if not r.get("ok", False):
        raise HTTPException(status_code=500, detail=r.get("error", "设置灰度比例失败"))
    logger.info("灰度部署比例已更新", extra={"event": "gray_update", "ratio": request.ratio})
    audit.audit("gray_update", ratio=request.ratio)
    return {"ratio": shield.get_gray_deploy_ratio(), "message": f"灰度拦截比例已设为 {int(request.ratio * 100)}%"}

# ── 输出护栏 / 敏感信息检测开关（Web 管理端开关） ──
@app.get("/api/v1/guardrails")
async def get_guardrails():
    """返回输出护栏与敏感检测的启用状态。"""
    if shield is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    return {
        "output_guardrail": shield.get_output_guardrail_enabled(),
        "sensitive_leak": shield.get_sensitive_leak_enabled(),
    }

class GuardrailReq(BaseModel):
    output_guardrail: Optional[bool] = None
    sensitive_leak: Optional[bool] = None

@app.post("/api/v1/guardrails")
async def set_guardrails(request: GuardrailReq):
    """运行时开关输出护栏与敏感检测（任一字段可单独更新）。"""
    if shield is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    if request.output_guardrail is not None:
        shield.set_output_guardrail_enabled(request.output_guardrail)
    if request.sensitive_leak is not None:
        shield.set_sensitive_leak_enabled(request.sensitive_leak)
    logger.info("护栏配置已更新", extra={"event": "guardrails_update",
                "output_guardrail": request.output_guardrail, "sensitive_leak": request.sensitive_leak})
    audit.audit("guardrails_update", output_guardrail=request.output_guardrail,
                sensitive_leak=request.sensitive_leak)
    return {
        "output_guardrail": shield.get_output_guardrail_enabled(),
        "sensitive_leak": shield.get_sensitive_leak_enabled(),
        "message": "护栏配置已更新",
    }

# ── 配置快照（Web 管理端创建/列表） ──
class SnapshotCreateReq(BaseModel):
    reason: str = Field(default="manual", max_length=100)

@app.get("/api/v1/snapshots")
async def list_config_snapshots():
    """列出已有配置快照。"""
    return {"snapshots": list_snapshots()}

@app.post("/api/v1/snapshots")
async def create_config_snapshot(request: SnapshotCreateReq):
    """创建配置快照（备份当前 shield 配置与学习状态）。"""
    if shield is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    r = create_snapshot(shield, reason=request.reason)
    if not r.get("ok", False):
        raise HTTPException(status_code=500, detail=r.get("error", "创建快照失败"))
    audit.audit("snapshot_create", id=r.get("id", ""), reason=request.reason)
    return r

class SnapshotRestoreReq(BaseModel):
    id: str = Field(..., min_length=1)

@app.post("/api/v1/snapshots/restore")
async def restore_config_snapshot(request: SnapshotRestoreReq):
    """恢复配置快照。返回快照中的配置数据，提示需重启网关使配置生效。"""
    r = restore_snapshot(request.id)
    if not r.get("ok", False):
        raise HTTPException(status_code=404, detail=r.get("error", "快照不存在"))
    audit.audit("snapshot_restore", id=r.get("id", ""), reason=r.get("reason", ""))
    return {"ok": True, "id": r.get("id", ""), "timestamp": r.get("timestamp", ""),
            "reason": r.get("reason", ""),
            "message": "已读取快照配置。请重启网关使恢复的配置生效（恢复涉及 shield 重建）。"}

# ── 告警通道配置（Web 管理端表单） ──
@app.get("/api/v1/notifiers/config")
async def get_notifiers_config():
    """返回当前已启用的告警通道。"""
    active = {}
    if alert_manager:
        for n in alert_manager._notifiers:
            active[n.channel_name] = n.config
    return {"channels": active}

class NotifiersSaveReq(BaseModel):
    channels: Dict[str, dict] = {}

@app.post("/api/v1/notifiers/config")
async def save_notifiers_config(request: NotifiersSaveReq):
    """批量配置告警通道。Body: {"channels": {"dingtalk": {"enabled": true, ...}, ...}}"""
    if alert_manager is None:
        raise HTTPException(status_code=503, detail="Alert manager not initialized")
    alert_manager.clear_notifiers()
    for channel_name, config in request.channels.items():
        cls = _NOTIFIER_CLASSES.get(channel_name)
        if cls and config.get("enabled", False):
            alert_manager.add_notifier(cls(config))
    logger.info("告警通道已更新", extra={"event": "notifiers_update",
                "active_channels": len(alert_manager._notifiers)})
    audit.audit("notifiers_update", active_channels=len(alert_manager._notifiers))
    return {"status": "ok", "active_channels": len(alert_manager._notifiers)}

class NotifierTestReq(BaseModel):
    channel: str = Field(...)
    config: dict = {}

@app.post("/api/v1/notifiers/test")
async def test_notifier(request: NotifierTestReq):
    """发送测试告警到指定通道。"""
    cls = _NOTIFIER_CLASSES.get(request.channel)
    if not cls:
        raise HTTPException(status_code=400, detail=f"未知告警通道: {request.channel}")
    test_event = AlertEvent(
        event_type="test", severity="info",
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        attack_category="test", trust_level="TEST", reject_stage="test",
        text_preview="这是一条来自玄盾网关的测试告警", engine_mode="gateway",
    )
    notifier = cls(request.config)
    ok = notifier.send(test_event)
    return {"status": "ok" if ok else "failed", "channel": request.channel}

# ── 企业 API Key 授权查询（只读，仅管理密钥可访问） ──
# 企业 API Key 由供应商（玄盾）离线签发（RS256 JWT），网关只负责验签与计量，
# 不支持自建。本组端点仅供企业管理端查看：公钥是否已配置、以及本网关
# 已产生流量的企业密钥的套餐/有效期/用量/吊销状态。

@app.get("/api/v1/keys")
async def list_api_keys():
    """列出本网关已产生流量的企业 API Key 授权信息（只读，不含密钥明文）。"""
    configured = _jwt.is_configured()
    keys = []
    if state_store:
        counters = state_store.get_all_counters()
        for name, usage in counters.items():
            if not name.startswith(_KEY_USAGE_PREFIX):
                continue
            jti = name[len(_KEY_USAGE_PREFIX):]
            meta = state_store.get_session(_KEY_META_PREFIX + jti) or {}
            keys.append({
                "jti": jti,
                "sub": meta.get("sub", ""),
                "tier": meta.get("tier", ""),
                "quota": meta.get("quota", 0),
                "exp": meta.get("exp", 0),
                "usage": usage,
                "revoked": _revoked.contains(jti),
            })
    keys.sort(key=lambda k: k["jti"])
    return {"configured": configured, "provider": "xuanDun", "keys": keys}

class KeyRevokeReq(BaseModel):
    jti: str = Field(..., min_length=1)

@app.post("/api/v1/keys/revoke")
async def revoke_api_key(req: KeyRevokeReq):
    """按 jti 吊销企业 API Key（软删除，立即失效，不可恢复）。"""
    ok = _revoked.add(req.jti)
    if not ok:
        raise HTTPException(status_code=404, detail="该 jti 已在吊销列表")
    audit.audit("api_key_revoke", jti=req.jti)
    logger.warning("企业 API Key 已吊销", extra={"event": "api_key_revoke", "jti": req.jti})
    return {"ok": True, "jti": req.jti}

@app.get("/")
async def root():
    return {"service": "玄盾 AI安全网关", "version": VERSION,
            "docs": "/docs", "health": "/health", "metrics": "/metrics",
            "models": "/api/v1/models", "status": "/api/v1/status", "reload": "/api/config/reload",
            "keys": "/api/v1/keys"}

if __name__ == "__main__":
    import uvicorn
    c = load_config()
    uvicorn.run("gateway.app:app", host=c.gateway.host, port=c.gateway.port, log_level=c.gateway.log_level)
