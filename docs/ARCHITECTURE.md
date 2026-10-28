# 个人版架构（内部）

> 内部文档，不对外发布。

## 一、三层管道

```
用户请求 → 本地代理拦截
    ↓
【第一层】请求侧脱敏（sanitizer.py）
    ├─ 扫描 API 密钥、手机号、邮箱、身份证、银行卡
    ├─ 根据策略：警告 / 阻断 / 打码
    └─ 打码后转发给中转站
    ↓
转发到中转站 → 中转站转发到模型 → 模型返回
    ↓
【第二层】响应侧完整性验证（verifier.py）
    ├─ Tool Call 危险参数检测（rm -rf / 反弹 shell / curl|sh / /etc/passwd）
    ├─ 系统提示词一致性（是否被注入）
    ├─ 响应模式异常（长度/结构突变 3σ）
    └─ 敏感信息泄露（中转站是否返回了不该返回的内容）
    ↓
【第三层】恢复脱敏内容（restorer.py）
    ├─ 将打码占位符恢复为原始值
    └─ 返回给 AI 工具
    ↓
记录到本地日志（storage/db.py）
```

### 关键实现细节

**占位符格式** `⟦XD_n⟧` —— 第 n 个脱敏位。restorer 会检查响应中是否出现
本会话**未登记**的占位符编号：本会话做过脱敏时那是中转站在探测原始值的信号
（阻断）；本会话从未脱敏时没有可置换的值，只记录（多为模型在复述该格式）。

**基线差分**（`baseline.py`）—— 同一会话内响应的长度/结构做 3σ 突变检测。
条件触发型攻击会在前 N 次调用中表现正常，只有基线能发现。

---

## 二、检测判据的固有暴露面

判据以明文存在于二进制中。这是**检测类产品的固有暴露面**：
要检测某类攻击，就必须知道它长什么样。

`tools/decompile_audit.py` 会静态列出当前产物里的判据文本，
用于评估是否需要外置或加密。注意该脚本只报**事实**，不判断「是否安全」。

---

## 三、与企业版的复用关系

```
个人版（personal/）
    │
    ├─ ★ 已内置（裁剪子集）──► src/daoti_xuandun/  共 16 个文件 / 615 KB
    │                          _check_output.py / sensitive_leak.py
    │                          _check_prompt_leak.py / tool_detector.py
    │                          xuandun.py / config.py / types.py / preprocessors.py
    │                          ancient_mapper.py / luoshu_mapper.py / reject_gate.py
    │                          secure_strings.py / dynamic_shell.py / timing_checker.py
    │                          _check_external.py
    │
    │   ★ 为什么是「裁剪入库」而不是「pip 依赖企业版 SDK」：
    │     原方案下护栏在生产包中 100% 缺失 —— 企业版包未发布到 PyPI，
    │     干净 clone 上装不上，而护栏不可用被 except 吞掉，
    │     提示词注入与敏感泄露两类检测静默失效，用户毫无感知。
    │     详见 GUARDRAIL_SYNC.md。
    │
    ├─ 未接入（请求侧）────► luoshu_mapper / reject_gate / dynamic_shell
    │                          ⚠️ 个人版**不加载**输入侧那一整条企业版管道：
    │                          reject_gate、动态壳、时序校验、外部内容检测
    │                          都是为「保护模型」设计的，与个人版要解决的
    │                          「中转站篡改返回」不是同一个问题。
    │
    │                          ★ 但「洛书编码」本身是需要的：
    │                          OutputGuardrail 内部**自带一个**独立的
    │                          LuoshuSymbolMapper 实例，只用于把文本编码成
    │                          语言无关向量，不共享输入侧的原型库。
    │                          所以「洛书映射器没被用到」这个说法不准确 ——
    │                          请求侧没接入，输出护栏内部在用。
    │
    └─ 全新实现 ────────────► sanitizer.py / verifier.py / restorer.py
                              baseline.py（请求基线差分）
                              reputation/tracker.py（信誉评估）
                              storage/db.py（个人版专属 SQLite）
                              proxy/app.py（个人版专属代理入口）
                              license.py（激活码验签）
                              src-tauri/src/license.rs（机器码采集）
                              src-tauri/src/tray.rs（系统托盘）
```

**护栏是仓库内置子集，不依赖任何外部包。** `pip install -e .` 即可获得完整防护能力。

---

## 四、流量路径上只有一个校验点

**这是安全架构里最容易被误解的一点。**

用户的 AI 工具把 API 地址填成 `127.0.0.1:18765`，请求直达引擎。
**流量完全不经过 Rust** —— Rust 只是看护进程 + WebView 壳。

```
AI 工具 ──HTTP──► 引擎（Python, :18765）──HTTP──► 中转站
                    ▲
                    └── 唯一的激活校验点
Rust（Tauri）不在这条路径上
```

因此「把校验点分散到 Rust 侧和引擎侧」这种说法**不成立** ——
早期注释曾这样描述过，是错的，已更正。
