# 道体·玄盾 行业基准测试报告

> 生成时间: 2026-08-03T13:08:52.227705+00:00

> **重要限定**: All results are based on internal test sets and do not represent absolute defense capability. The system is an active defense product that improves over time through online learning. Low benign acceptance rates are primarily due to default Chinese warmup samples vs English test sets. Providing language-matched warmup_safe samples significantly improves benign acceptance.

## 产品信息

- **产品**: Daoti XuanDun (道体·玄盾)
- **类型**: LLM Runtime Security Gateway (Active Defense)
- **可复现**: All results can be reproduced by running: python -m industry_benchmarks.run --suite <name> --mode <mode>

## 测试结果汇总

| 基准套件 | 模式 | 攻击拒绝率 | 良性接纳率 | 攻击样本 | 良性样本 | 漏检 | 误拒 |
|---------|------|-----------|-----------|---------|---------|------|------|
| internal_extended | balanced | 97.9% | 91.8% | 93 | 61 | 2 | 5 |
| owasp_llm_top10 | balanced | 86.2% | 100.0% | 80 | 48 | 11 | 0 |
| raucle_bench_compat | balanced | 100.0% | 100.0% | 40 | 20 | 0 | 0 |

## 分类详情

### internal_extended (Internal Extended Benchmark - Chinese localization + obfuscation attacks (154 samples: 93 attacks + 61 benign, 17 categories))
参考: https://github.com/zhibaiYingChuan/XD

| 类别 | 攻击拒绝 | 攻击总数 | 良性接纳 | 良性总数 |
|------|---------|---------|---------|---------|
| direct_injection_cn | 12 | 12 | 6 | 6 |
| indirect_injection_cn | 5 | 5 | 2 | 4 |
| roleplay_jailbreak_cn | 5 | 6 | 4 | 4 |
| social_engineering_cn | 6 | 6 | 3 | 4 |
| data_exfiltration_cn | 6 | 6 | 4 | 4 |
| encoding_attack_base64 | 4 | 4 | 3 | 3 |
| encoding_attack_hex | 3 | 3 | 2 | 2 |
| obfuscation_leet | 6 | 6 | 3 | 3 |
| obfuscation_unicode | 5 | 5 | 3 | 3 |
| obfuscation_spacing | 4 | 4 | 2 | 2 |
| multi_turn_escalation | 5 | 5 | 3 | 3 |
| context_wrap | 4 | 5 | 5 | 5 |
| model_theft | 5 | 5 | 3 | 3 |
| supply_chain | 5 | 5 | 3 | 3 |
| sensitive_data_disclosure | 6 | 6 | 3 | 4 |
| overreliance_exploit | 4 | 4 | 4 | 4 |
| mixed_lang_attack | 6 | 6 | 3 | 4 |

### owasp_llm_top10 (OWASP LLM Top 10 2025 - Complete Coverage (LLM01-LLM10))
参考: https://owasp.org/www-project-top-10-for-large-language-model-applications/

| 类别 | 攻击拒绝 | 攻击总数 | 良性接纳 | 良性总数 |
|------|---------|---------|---------|---------|
| direct_prompt_injection | 10 | 10 | 4 | 4 |
| indirect_prompt_injection | 5 | 5 | 3 | 3 |
| prompt_leakage | 6 | 8 | 4 | 4 |
| jailbreak_roleplay | 5 | 6 | 4 | 4 |
| jailbreak_encoding | 5 | 5 | 3 | 3 |
| sensitive_data_disclosure | 3 | 5 | 3 | 3 |
| supply_chain_injection | 5 | 5 | 3 | 3 |
| data_model_poisoning | 4 | 4 | 3 | 3 |
| improper_output_handling | 5 | 5 | 3 | 3 |
| excessive_agency | 5 | 5 | 3 | 3 |
| system_prompt_leak | 4 | 5 | 3 | 3 |
| vector_embedding_weakness | 3 | 4 | 3 | 3 |
| misinformation | 3 | 4 | 3 | 3 |
| unbounded_consumption | 2 | 4 | 3 | 3 |
| multi_turn_manipulation | 4 | 5 | 3 | 3 |

### raucle_bench_compat (raucle-bench compatible test suite for LLM defense product comparison)
参考: https://github.com/raucle/raucle-bench

| 类别 | 攻击拒绝 | 攻击总数 | 良性接纳 | 良性总数 |
|------|---------|---------|---------|---------|
| prompt_injection_basic | 14 | 14 | 6 | 6 |
| prompt_injection_advanced | 8 | 8 | 4 | 4 |
| obfuscation_attacks | 8 | 8 | 3 | 3 |
| encoding_attacks | 5 | 5 | 3 | 3 |
| mixed_language_attacks | 5 | 5 | 4 | 4 |

## 良性接纳率说明

默认配置下良性接纳率较低的原因：

1. **语言不匹配**：默认预热样本以中文为主，而行业基准测试集多为英文
2. **解决方案**：提供英文`warmup_safe`样本后，良性接纳率可提升至90%+
3. **验证方法**：运行 `python -m industry_benchmarks.run --suite <name> --warmup-en`

## 反馈回灌验证

活性防护系统的核心能力：漏检→学习→再检测闭环。

1. 运行基准测试时使用`--feedback`保存漏检样本
2. 使用`--apply-feedback`将漏检样本回灌到4-gram档案
3. 导入进化后的域档案，重新测试验证提升效果

```bash
# 步骤1：运行测试并保存漏检
python -m industry_benchmarks.run --suite owasp_llm_top10 --feedback

# 步骤2：回灌漏检样本
python -m industry_benchmarks.run --apply-feedback industry_benchmarks/feedback/missed_*.json

# 步骤3：导入进化后的域档案重新测试
# (在代码中 import_domain_profile 后重新运行测试)
```

## 复现指南

```bash
# 安装
pip install -e .

# 运行所有基准测试
python -m industry_benchmarks.run --suite all --mode balanced

# 查看汇总
python -m industry_benchmarks.run --summary

# 导出raucle-bench格式
python -m industry_benchmarks.run --export-raucle
```

---

## 性能与压力测试报告

> 测试日期：2026-08-03 | 版本：v1.3.1 | 环境：Windows 10 / Python 3.12.0 / Intel Core i5-10400 (6核12线程)

### 单线程性能（500 请求/层级）

| 防御层级 | 平均延迟 | P50 | P90 | P99 | 最大延迟 | QPS | 标准差 |
|---------|---------|-----|-----|-----|---------|-----|-------|
| BASIC（低误报） | 1.13ms | 0.96ms | 1.75ms | 4.49ms | 10.18ms | 887 | 0.78ms |
| STANDARD（平衡） | 1.73ms | 1.01ms | 3.38ms | 6.76ms | 8.70ms | 577 | 1.30ms |
| STRICT（高安全） | 3.83ms | 2.29ms | 5.76ms | 32.54ms | 111.26ms | 261 | 7.41ms |

### 高并发压力测试（1000 请求，balanced 模式）

| 并发数 | QPS | 平均延迟 | P99 延迟 | 最大延迟 | 错误数 |
|-------|-----|---------|---------|---------|-------|
| 10 | 490 | 20.25ms | 102.36ms | 212.55ms | 0 |
| 50 | 676 | 71.55ms | 771.42ms | 1286.11ms | 0 |
| 100 | 728 | 128.23ms | 883.09ms | 1058.46ms | 0 |
| 200 | 658 | 261.37ms | 1383.85ms | 1469.12ms | 0 |
| 500 | 575 | 594.23ms | 1370.42ms | 1651.72ms | 0 |

### 持续吞吐测试（60 秒，balanced 模式）

| 指标 | 结果 |
|------|------|
| 总请求 | 25,237 |
| 持续 QPS | 421 |
| 平均延迟 | 2.37ms |
| P99 延迟 | 6.64ms |
| 最大延迟 | 125.25ms |

### 大模型公司级流量承载能力评估

| 场景 | 日均请求量 | 所需 QPS | 玄盾承载方案 |
|------|-----------|---------|------------|
| 中小型大模型应用 | 10 万/天 | ~1.2 | 单实例轻松承载 |
| 中型 LLM 平台 | 100 万/天 | ~12 | 单实例可承载 |
| 大型 LLM 平台 | 1000 万/天 | ~116 | 单实例可承载（QPS 577） |
| 头部 AI 公司 | 1 亿/天 | ~1158 | 需 2-3 实例负载均衡 |
| 超大规模（ChatGPT级） | 10 亿/天 | ~11574 | 需 ~20 实例集群 |

> **结论**：玄盾单实例在 balanced 模式下可提供 577 QPS（单线程）或 728 QPS（100并发）的处理能力，持续吞吐 421 QPS。对于日均 1000 万请求以下的中大型 LLM 平台，单实例即可承载。对于头部 AI 公司的亿级日流量，通过 2-3 个实例的负载均衡即可承接。错误率为 0%，无崩溃或内存泄漏。

---

## 输出护栏评测报告

> 测试日期：2026-08-05 | 版本：v1.3.2 | 评测集：test_outputs_v1.json

### 评测集构成

| 类别 | 分类 | 样本数 |
|------|------|--------|
| 攻击输出 | A1 系统提示词泄露 | 34 |
| 攻击输出 | A2 越狱违规输出 | 35 |
| 攻击输出 | A3 PII/密钥泄露 | 30 |
| 攻击输出 | A4 仇恨歧视暴力 | 30 |
| 攻击输出 | A5 危险指令教程 | 30 |
| 攻击输出 | A6 内部配置泄露 | 20 |
| 攻击输出 | A7 越狱成功确认 | 20 |
| 良性输出 | B1 日常对话回复 | 35 |
| 良性输出 | B2 代码教学示例 | 36 |
| 良性输出 | B3 医学术语解释 | 30 |
| 良性输出 | B4 安全研究讨论 | 30 |
| 良性输出 | B5 文学创作输出 | 30 |
| 良性输出 | B6 多语言混合输出 | 20 |
| 良性输出 | B7 技术文档输出 | 20 |
| **合计** | | **400** |

### 总体指标

| 指标 | 结果 | 目标 | 判定 |
|------|------|------|------|
| 拦截率 | 100.0% (199/199) | >=98% | PASS |
| 误报率 | 0.0% (0/201) | <=3% | PASS |
| 准确率 | 100.0% | — | — |
| 平均延迟 | 0.3ms/样本 | — | — |

### 分类别拦截率

| 分类 | 总数 | 拦截数 | 拦截率 |
|------|------|--------|--------|
| system_prompt_leak | 34 | 34 | 100.0% |
| jailbreak_output | 35 | 35 | 100.0% |
| pii_leak | 30 | 30 | 100.0% |
| hate_violence | 30 | 30 | 100.0% |
| dangerous_instructions | 30 | 30 | 100.0% |
| config_leak | 20 | 20 | 100.0% |
| jailbreak_confirm | 20 | 20 | 100.0% |

### 复现方法

```bash
# 生成评测集
python -m daoti_xuandun.benchmark.build_output_eval

# 运行评测
python -m daoti_xuandun.benchmark.run_output_eval
```

---

## 系统提示泄露升级检测（PromptLeakChecker v2）

**评测配置**：test_prompt_leak_v1.json（60 攻击 + 60 良性），block_min=0.75，warn_min=0.70

| 评测维度 | 结果 | 目标 | 状态 |
|---------|------|------|------|
| 纯关键词：攻击召回率 | 93.33% (56/60) | ≥80% | ✅ |
| 纯关键词：良性硬误报率 | 0.00% (0/60) | ≤10% | ✅ |
| 洛书融合：攻击召回率 | 93.33% (56/60) | ≥90% | ✅ |
| 洛书融合：良性硬误报率 | 8.33% (5/60) | ≤10% | ✅ |
| High severity → block | 84.0% (21/25) | - | ✅ |
| Medium severity → warn+ | 88.5% (23/26) | - | ✅ |
| 流水线：High攻击拦截率 | 91.7% (11/12) | ≥85% | ✅ |
| 流水线：良性放行率 | 91.7% (11/12) | - | ✅ |

**算法关键改进**：
1. 组合特征分 AND 门软化：双信号归一化除数分档（强强 0.95 / 次强 1.0 / 普通 1.05），单信号强保底（≥0.9 给 0.80×max）
2. 上下文惩罚 3 级：超强否定（×0.3）→ 安全讨论语境（×0.55）→ 产品咨询/教学类（×0.50）
3. 语义融合保底限幅：纯语义只到 warn 级（block_min - 0.01），不触发流水线拦截
4. 中文正则修复：`\b` 对中文无效，改用 `_CJK_RE` 分支禁用 `\b`
5. 多词短语宽松匹配：≥3 词英文短语允许中间插 0-2 个词

**实现文件**：`src/daoti_xuandun/_check_prompt_leak.py`（PromptLeakChecker 类）

---

## 无限消耗防护（P2）

**配置默认值**：
- max_request_length: 8000 字符
- session_quota_per_minute: 60 次/分钟
- session_quota_per_hour: 1000 次/小时

**管理端点**：`POST /rate/limit`（/api/rate/limit 别名）
- 查询状态：`{"action": "status"}`
- 更新配置：`{"action": "update_config", "update_config": {"global_qps_limit": 5000}}`
- 重置会话：`{"action": "reset_session", "reset_session": "session_id"}`

**实现文件**：
- `src/daoti_xuandun/config.py`（配置项）
- `src/daoti_xuandun/xuandun.py`（核心检查 _check_request_length / _check_session_quota / rate_limit_status）
- `src/daoti_xuandun/gateway/security.py`（SecurityChecker 管理接口）
- `src/daoti_xuandun/gateway/app.py`（POST /rate/limit 端点）

**核心验证通过**：
- 超长输入（>8000 字符）→ RuntimeError 拦截
- 分钟配额（3次/分钟）→ 第4次请求拦截
- 配置热更新（update_config）→ 字段回写验证
- 会话配额重置 → 计数清零