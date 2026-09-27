<!--
SPDX-License-Identifier: DaoTi-Research-1.0
Copyright (c) 2026 独立研究者，知白
-->

# 个人版内置护栏层（daoti_xuandun 子集）

## 这是什么

个人版通过 `verifier._try_load_guardrail()` 复用企业版的**输出护栏**，
补上个人版自研检测层没有的两类判据：

| 判据 | 防护对象 |
|---|---|
| `system_prompt_inject` | 提示词注入 / 越狱指令 |
| `sensitive_leak` | 身份证、银行卡、密钥等 PII 外泄 |

缺了它，个人版的拦截能力比文档描述少两层 —— 且**用户无从察觉**
（界面照常显示「防护中」）。2026-09 的一次全角度审查发现了这个缺陷。

## 为什么是「子集」而不是整个 daoti_xuandun

`daoti_xuandun` 完整包 2.2 MB，`__init__.py` 会连带导入
`reject_gate`（196KB）、`xuandun`（102KB）、`preprocessors`（78KB）、
`luoshu_mapper`（42KB）等重型模块，以及 `benchmark/`、`gateway/`、
`integrations/` 等个人版完全用不到的目录。

本目录只保留**护栏功能的最小依赖闭包**：

```
config.py           配置与密钥（被护栏引用）
types.py            类型定义
preprocessors.py    关键词解混淆（_check_output 依赖）
luoshu_mapper.py    洛书映射（_check_output 依赖）
_check_output.py    ★ 输出护栏本体
sensitive_leak.py   ★ 敏感泄露检测本体
xuandun.py          XuanDun 主类（个人版 verifier 的入口）
__init__.py         仅导出护栏所需符号
```

实测验证过这个闭包可独立工作：

```
OutputGuardrail OK
  注入样本 -> block high
  正常样本 -> pass pass
SensitiveLeakDetector OK
```

## 为什么不直接把企业版整个目录复制过来

1. **体积**：2.2MB → 约 350KB，Nuitka 编译时间与安装包体积都受益
2. **避免误引入**：企业版 `config.py` 里有
   `shell_key = b"daoti_xuandun_16"` / `mapping_key = b"ancient_map_16b!"`
   两处**硬编码明文 fallback 密钥**。它们只在
   `XUANDUN_REQUIRE_SECURE_KEY=1` 时才会被拒绝 ——
   个人版打包时没有设这个变量，等于把公开密钥打进二进制。
   （这属于反编译加固范畴，见 TODO）
3. **边界清晰**：个人版不需要网关、计费、benchmark 等能力

## 同步机制

本目录是**从企业版裁剪同步**的副本，不是权威源。
权威源在企业版仓库的 `src/daoti_xuandun/`。

升级护栏能力时：
1. 在企业版改 `config.py` / `preprocessors.py` / `luoshu_mapper.py` /
   `_check_output.py` / `sensitive_leak.py` / `xuandun.py`
2. 同步对应文件到本目录
3. 跑 `python tests/test_guardrail_parity.py` 确认行为一致

## 测试

`tests/test_guardrail_parity.py` 验证：
- 本目录能独立 import 并完成检测
- 注入样本被拦、正常样本放行（防「护栏加载成功但形同虚设」）
- 关键检测能力与统计口径可被 `check_degradation.py` 查询

## 许可证

同属道体研究许可证 v1.0。与企业版同源，版权归同一作者。
