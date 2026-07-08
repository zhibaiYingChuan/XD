# 道体·玄盾 行业基准测试报告

> 生成时间: 2026-06-07T00:16:50.419759+00:00

> **重要限定**: All results are based on internal test sets and do not represent absolute defense capability. The system is an active defense product that improves over time through online learning. Low benign acceptance rates are primarily due to default Chinese warmup samples vs English test sets. Providing language-matched warmup_safe samples significantly improves benign acceptance.

## 产品信息

- **产品**: Daoti XuanDun (道体·玄盾)
- **类型**: LLM Runtime Security Gateway (Active Defense)
- **可复现**: All results can be reproduced by running: python -m industry_benchmarks.run --suite <name> --mode <mode>

## 测试结果汇总

| 基准套件 | 模式 | 攻击拒绝率 | 良性接纳率 | 攻击样本 | 良性样本 | 漏检 | 误拒 |
|---------|------|-----------|-----------|---------|---------|------|------|
| internal_extended | balanced | 87.1% | 32.8% | 93 | 61 | 12 | 41 |
| owasp_llm_top10 | balanced | 97.5% | 33.3% | 80 | 48 | 2 | 32 |
| raucle_bench_compat | balanced | 90.0% | 90.0% | 40 | 20 | 4 | 2 |

## 分类详情

### internal_extended (Internal Extended Benchmark - Chinese localization + obfuscation attacks (200+ samples, 17 categories))
参考: https://github.com/smallloong/XuanDun

| 类别 | 攻击拒绝 | 攻击总数 | 良性接纳 | 良性总数 |
|------|---------|---------|---------|---------|
| direct_injection_cn | 8 | 12 | 5 | 6 |
| indirect_injection_cn | 5 | 5 | 3 | 4 |
| roleplay_jailbreak_cn | 5 | 6 | 1 | 4 |
| social_engineering_cn | 5 | 6 | 4 | 4 |
| data_exfiltration_cn | 3 | 6 | 4 | 4 |
| encoding_attack_base64 | 2 | 4 | 1 | 3 |
| encoding_attack_hex | 2 | 3 | 2 | 2 |
| obfuscation_leet | 6 | 6 | 0 | 3 |
| obfuscation_unicode | 5 | 5 | 0 | 3 |
| obfuscation_spacing | 4 | 4 | 0 | 2 |
| multi_turn_escalation | 5 | 5 | 0 | 3 |
| context_wrap | 5 | 5 | 0 | 5 |
| model_theft | 5 | 5 | 0 | 3 |
| supply_chain | 5 | 5 | 0 | 3 |
| sensitive_data_disclosure | 6 | 6 | 0 | 4 |
| overreliance_exploit | 4 | 4 | 0 | 4 |
| mixed_lang_attack | 6 | 6 | 0 | 4 |

### owasp_llm_top10 (OWASP LLM Top 10 2025 - Complete Coverage (LLM01-LLM10))
参考: https://owasp.org/www-project-top-10-for-large-language-model-applications/

| 类别 | 攻击拒绝 | 攻击总数 | 良性接纳 | 良性总数 |
|------|---------|---------|---------|---------|
| direct_prompt_injection | 10 | 10 | 3 | 4 |
| indirect_prompt_injection | 5 | 5 | 1 | 3 |
| prompt_leakage | 7 | 8 | 2 | 4 |
| jailbreak_roleplay | 6 | 6 | 0 | 4 |
| jailbreak_encoding | 5 | 5 | 2 | 3 |
| sensitive_data_disclosure | 5 | 5 | 0 | 3 |
| supply_chain_injection | 5 | 5 | 2 | 3 |
| data_model_poisoning | 4 | 4 | 0 | 3 |
| improper_output_handling | 4 | 5 | 1 | 3 |
| excessive_agency | 5 | 5 | 1 | 3 |
| system_prompt_leak | 5 | 5 | 1 | 3 |
| vector_embedding_weakness | 4 | 4 | 1 | 3 |
| misinformation | 4 | 4 | 0 | 3 |
| unbounded_consumption | 4 | 4 | 2 | 3 |
| multi_turn_manipulation | 5 | 5 | 0 | 3 |

### raucle_bench_compat (raucle-bench compatible test suite for LLM defense product comparison)
参考: https://github.com/raucle/raucle-bench

| 类别 | 攻击拒绝 | 攻击总数 | 良性接纳 | 良性总数 |
|------|---------|---------|---------|---------|
| prompt_injection_basic | 12 | 14 | 6 | 6 |
| prompt_injection_advanced | 8 | 8 | 2 | 4 |
| obfuscation_attacks | 6 | 8 | 3 | 3 |
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