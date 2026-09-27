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
    marked_safe   INTEGER NOT NULL DEFAULT 0      -- ★ P1-9：用户手动标记为误报
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_type      ON logs(log_type);
CREATE INDEX IF NOT EXISTS idx_logs_domain    ON logs(relay_domain);
CREATE INDEX IF NOT EXISTS idx_logs_action    ON logs(action);
-- 注：新增列（marked_safe 等）的向后兼容迁移在 db.py::_init_schema 中用
--     PRAGMA table_info 检测后按需 ALTER，避免老库缺列 / 新库重复报错。

-- ══════════════════════════════════════════════════════════════
-- 脱敏记录表（保存原始敏感值，仅存本地）
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS redaction_records (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT    NOT NULL,
    log_id        INTEGER,                       -- 关联 logs.id
    redaction_idx INTEGER NOT NULL,               -- 占位符编号
    category      TEXT    NOT NULL,              -- api_key/phone/email/...
    original      TEXT    NOT NULL,              -- ★ 原始敏感值（仅本地）
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
    notes              TEXT    NOT NULL DEFAULT '[]'
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
