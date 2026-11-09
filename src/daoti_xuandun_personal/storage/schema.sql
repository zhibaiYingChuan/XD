-- SPDX-License-Identifier: DaoTi-Research-1.0
-- Copyright (c) 2026 独立研究者，知白
-- 个人版本地存储表结构
--
-- 设计原则：
-- 1. 数据 100% 本地，用户完全掌控
-- 2. 敏感原始值存于 redaction_records 表，加密列由应用层处理
-- 3. 日志表用 WAL 模式提升并发读性能

-- ══════════════════════════════════════════════════════════════
-- 安全日志表
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     REAL    NOT NULL,              -- Unix 时间戳
    log_type      TEXT    NOT NULL,              -- request_sanitize/response_verify/proxy_error/relay
    relay_domain  TEXT    NOT NULL DEFAULT '',   -- 中转站域名
    action        TEXT    NOT NULL,              -- pass/redact/block/alert
    severity      TEXT    NOT NULL DEFAULT 'low',-- low/medium/high
    model         TEXT    NOT NULL DEFAULT '',
    finding_count INTEGER NOT NULL DEFAULT 0,
    summary       TEXT    NOT NULL DEFAULT '',   -- 人类可读摘要
    detail_json   TEXT    NOT NULL DEFAULT '{}', -- 发现项详情（JSON）
    text_preview  TEXT    NOT NULL DEFAULT '',   -- 内容预览（已脱敏）
    marked_safe   INTEGER NOT NULL DEFAULT 0,     -- ★ P1-9：用户手动标记为误报
    -- ★ 2026-10-20：本条日志打了几处码。
    --   脱敏明细会在同会话的下一次响应时被清除（clear_redactions_for_session），
    --   所以「打码数」必须落在日志行上，否则状态栏的「已打码 N 处」
    --   在日志里没有任何可下钻的记录 —— 筛选「已打码」永远 0 条。
    redaction_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_type      ON logs(log_type);
CREATE INDEX IF NOT EXISTS idx_logs_domain    ON logs(relay_domain);
CREATE INDEX IF NOT EXISTS idx_logs_action    ON logs(action);
-- 注：新增列（marked_safe 等）的向后兼容迁移在 db.py::_init_schema 中用
--     PRAGMA table_info 检测后按需 ALTER，避免老库缺列 / 新库重复报错。

-- ══════════════════════════════════════════════════════════════
-- 脱敏记录表（只保存**掩码后**的原文，不存明文）
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS redaction_records (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT    NOT NULL,
    log_id        INTEGER,                       -- 关联 logs.id
    redaction_idx INTEGER NOT NULL,               -- 占位符编号
    category      TEXT    NOT NULL,              -- api_key/phone/email/...
    original      TEXT    NOT NULL,              -- ★ 掩码值（前 4 + 长度 + 尾 2），不是明文
    redacted      TEXT    NOT NULL,              -- 占位符
    start_pos     INTEGER NOT NULL DEFAULT 0,
    end_pos       INTEGER NOT NULL DEFAULT 0,
    created_at    REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_redaction_session ON redaction_records(session_id);
CREATE INDEX IF NOT EXISTS idx_redaction_log     ON redaction_records(log_id);

-- ══════════════════════════════════════════════════════════════
-- 中转站信誉表
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS relay_reputation (
    domain             TEXT    PRIMARY KEY,
    score              INTEGER NOT NULL DEFAULT 100,
    first_seen         REAL    NOT NULL,
    last_seen          REAL    NOT NULL,
    total_calls        INTEGER NOT NULL DEFAULT 0,
    danger_count       INTEGER NOT NULL DEFAULT 0,
    suspect_count      INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms     REAL    NOT NULL DEFAULT 0,
    latency_samples    INTEGER NOT NULL DEFAULT 0,
    known_malicious    INTEGER NOT NULL DEFAULT 0,
    watermark_detected INTEGER NOT NULL DEFAULT 0,
    notes              TEXT    NOT NULL DEFAULT '[]',
    -- ★ v0.1.0：中转站责任与用户自身责任分列。
    --   只有 relay_* 参与评分（见 tracker._RELAY_ATTRIBUTABLE）。
    --   旧的 danger_count/suspect_count 保留为两者之和，供展示沿用。
    relay_danger_count   INTEGER NOT NULL DEFAULT 0,
    self_danger_count    INTEGER NOT NULL DEFAULT 0,
    relay_suspect_count  INTEGER NOT NULL DEFAULT 0,
    self_suspect_count   INTEGER NOT NULL DEFAULT 0
);

-- ══════════════════════════════════════════════════════════════
-- 配置表（key-value）
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  REAL NOT NULL
);

-- ══════════════════════════════════════════════════════════════
-- 响应模式基线表（会话级长度/结构基线）
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS pattern_baseline (
    session_id  TEXT NOT NULL,
    window_idx  INTEGER NOT NULL,                -- 滑动窗口索引
    length      INTEGER NOT NULL,
    signature   TEXT NOT NULL,                    -- 结构签名
    created_at  REAL NOT NULL,
    PRIMARY KEY (session_id, window_idx)
);

CREATE INDEX IF NOT EXISTS idx_pattern_session ON pattern_baseline(session_id);

-- ══════════════════════════════════════════════════════════════
-- 请求基线表（★ v0.1.0 新增，检测中转站篡改的关键对照物）
--
-- 为什么必须有这张表：
--   此前响应侧检测器在架构上从未接触过请求上下文，verifier.verify()
--   的签名里没有任何请求参数，app.py 转发前也不记录 tools /
--   tool_choice / system prompt。判据只能是「这段响应文本长得像不像 X」，
--   而中转站的攻击方向恰好是使用不含任何被禁词的载荷 —— 9/13 绕过。
--
--   有了这张表，判据变成「响应是否偏离了请求本身声明的东西」：
--   返回未声明的工具 / 换了模型 / 引入请求里没有的域名与依赖。
--   判据来源是请求本身（可信对照物），不依赖被评判的模型，
--   因此不存在循环论证。
--
-- 隐私：只存哈希与结构摘要，绝不存 system prompt 原文。
--       比对用哈希既够用又避免把提示词落盘。
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS request_baseline (
    session_id      TEXT PRIMARY KEY,
    model           TEXT NOT NULL DEFAULT '',       -- 用户请求的模型
    tools_hash      TEXT NOT NULL DEFAULT '',       -- tools 声明的哈希
    tool_names      TEXT NOT NULL DEFAULT '[]',     -- 工具名列表（JSON）
    system_hash     TEXT NOT NULL DEFAULT '',       -- system prompt 哈希
    system_len      INTEGER NOT NULL DEFAULT 0,
    msg_count       INTEGER NOT NULL DEFAULT 0,
    response_model  TEXT NOT NULL DEFAULT '',       -- 中转站返回的模型（比对用）
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_request_baseline_created
    ON request_baseline(created_at);

-- ══════════════════════════════════════════════════════════════
-- 模型别名台账（★ 2026-11-10：用「变化检测」替代「命名枚举」）
--
-- 为什么需要这张表
-- ────────────────────────────────────────────────────────────
-- 原判据是「返回的模型名是不是请求名的合法写法」，只能靠**枚举**
-- 命名形态来判定：-1017 快照、-cm 渠道、-dedicated 部署……
-- 每漏一种就刷一批误报，而服务商的命名是开放集合 ——
-- 枚举永远追不上，这类误报注定反复发生。
--
-- 真正的判据是**变化**，不是「长得像不像」：
--   · 第一次见到 (请求模型 → 返回模型) 这个组合：记录，提示一次；
--   · 之后稳定不变：静默（它就是这个中转站的正常写法）；
--   · 突然变了：告警 —— 这才是「被换了」的可核事实。
--
-- status:
--   auto       首次观察自动记录
--   confirmed  用户确认「这是同一个模型」，之后彻底静默
--   rejected   用户确认「确实被换了」，之后继续告警
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS model_alias (
    relay_domain   TEXT NOT NULL,
    request_model  TEXT NOT NULL,              -- 归一化后的请求模型
    response_model TEXT NOT NULL,              -- 归一化后的返回模型
    status         TEXT NOT NULL DEFAULT 'auto',
    seen_count     INTEGER NOT NULL DEFAULT 1,
    first_seen     REAL NOT NULL,
    last_seen      REAL NOT NULL,
    PRIMARY KEY (relay_domain, request_model, response_model)
);

CREATE INDEX IF NOT EXISTS idx_model_alias_lookup
    ON model_alias(relay_domain, request_model);

-- ══════════════════════════════════════════════════════════════
-- 陌生端点台账（★ 2026-11-10，与 model_alias 同一套机制）
--
-- 为什么需要它
-- ────────────────────────────────────────────────────────────
-- new_external_endpoint 的判据是「工具调用参数里出现了请求正文
-- 没提过的域名」。它不知道用户的意图就是访问那个地址 ——
-- AI 编程助手在一个会话里反复调同一个接口是**常态**，
-- 于是每轮一条告警，首页「可疑」一直涨，用户学会忽略它。
--
-- 与模型命名差异是同一个病：判据只能看「认不认识」，
-- 而判据真正该看的是「变没变」。
--
--   · 第一次见到某中转站返回这个端点：记录，提示一次；
--   · 之后稳定出现：静默（它就是这次任务的正常依赖）；
--   · 突然换成一个新端点：告警 —— 那才是值得看的变化。
--
-- status:
--   auto       首次观察自动记录
--   confirmed  用户确认「这是我在用的地址」，之后彻底静默
--   rejected   用户确认「这个地址不该出现」，之后继续告警
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS endpoint_allowance (
    relay_domain  TEXT NOT NULL,
    host          TEXT NOT NULL,               -- 小写域名或 IP
    status        TEXT NOT NULL DEFAULT 'auto',
    seen_count    INTEGER NOT NULL DEFAULT 1,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    PRIMARY KEY (relay_domain, host)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_allowance_lookup
    ON endpoint_allowance(relay_domain);

-- ══════════════════════════════════════════════════════════════
-- 凭证来源台账（2026-10-23）
--
-- 为什么要有这张表
-- ────────────────────────────────────────────────────────────
-- 「这枚 token 是你自己的工具带进来的，还是中转站返回的？」
-- 只靠单条日志答不了 —— 请求侧只看得见「它现在在请求里」。
-- 台账按指纹记录**首次出现**的方向与角色：
--   direction=request  → 用户这边先出现的（手打 / 工具返回 / 历史）
--   direction=response → 中转站的回复里先出现的
-- 后者且「本次请求从未发送过」时，才是可以拿去对质的证据。
--
-- 隐私：只存 SHA-256 指纹、打码片段与长度，**不存原文**。
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS credential_events (
    fingerprint TEXT PRIMARY KEY,              -- SHA-256(凭证原文)
    session_id  TEXT NOT NULL DEFAULT '',
    direction   TEXT NOT NULL,                 -- request / response
    role        TEXT NOT NULL DEFAULT '',      -- 用户提问 / 工具返回 / 模型回复 …
    category    TEXT NOT NULL,                 -- jwt / api_key / email …
    masked      TEXT NOT NULL DEFAULT '',       -- 前 4 + 长度 + 尾 2
    length      INTEGER NOT NULL DEFAULT 0,
    first_seen  REAL NOT NULL,
    log_id      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_credential_first_seen
    ON credential_events(first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_credential_session
    ON credential_events(session_id);

-- ══════════════════════════════════════════════════════════════
-- 每日统计表（首页 KPI 卡片数据源）
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS daily_stats (
    date            TEXT PRIMARY KEY,            -- YYYY-MM-DD
    total_calls     INTEGER NOT NULL DEFAULT 0,
    danger_count    INTEGER NOT NULL DEFAULT 0,
    suspect_count   INTEGER NOT NULL DEFAULT 0,
    safe_count      INTEGER NOT NULL DEFAULT 0,
    redaction_count INTEGER NOT NULL DEFAULT 0
);
