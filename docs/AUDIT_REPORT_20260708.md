# 道体·玄盾 项目全面审计报告

> **审计日期**：2026-07-08
> **审计范围**：src/daoti_xuandun、desktop/xuandun-desktop、industry_benchmarks、docs
> **审计方法**：静态代码分析 + 模式匹配 + 文档一致性核对

---

## 一、审计结论

| 维度 | 评级 | 说明 |
|------|------|------|
| 代码安全性 | ✅ 良好 | 无 SQL 注入、命令注入、pickle 反序列化、eval/exec 风险 |
| 代码质量 | ⚠️ 中等 | Rust 端有 unwrap()/expect() 滥用，锁处理基本正确 |
| 功能完整性 | ⚠️ 中等 | db.rs 新增快照功能未暴露为 Tauri 命令；updater 框架已集成但未配置 |
| 文档一致性 | ⚠️ 中等 | 白皮书已修正大部分不实声明，仍有少量待优化 |
| 测试覆盖 | ⚠️ 中等 | Rust 14个测试通过，前端17个测试通过，但关键路径覆盖不足 |

---

## 二、确认的真实问题

### 🔴 HIGH（4项）

#### H1：updater 插件已注册但未配置

- **文件**：[tauri.conf.json](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/tauri.conf.json)
- **问题**：`Cargo.toml` 声明了 `tauri-plugin-updater = "2"`，`lib.rs:22` 注册了插件，但 `tauri.conf.json` 中**没有** `plugins.updater` 配置段（缺少 `endpoints` 和 `pubkey`）。
- **影响**：自动更新功能无法实际工作。白皮书中已标注"框架已集成"，但用户可能误解为可用。
- **修复**：在 tauri.conf.json 中添加 updater 配置段，或明确标注为"待配置"。

#### H2：db.rs 新增快照功能未暴露为 Tauri 命令

- **文件**：[db.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/db.rs) L167-212、[commands.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/commands.rs)、[lib.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/lib.rs) L44-63
- **问题**：db.rs 实现了 `create_snapshot`、`list_snapshots`、`restore_snapshot` 三个方法，但 commands.rs 没有对应的 `#[tauri::command]` 函数，lib.rs 的 `invoke_handler` 也没有注册。前端 tauriApi.ts 自然也没有调用。
- **影响**：白皮书声称的"配置快照与回退"功能在桌面端不可用。
- **修复**：在 commands.rs 添加三个命令函数，在 lib.rs 注册，在 tauriApi.ts 添加调用。

#### H3：前端缺少代理控制 API 封装

- **文件**：[tauriApi.ts](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src/services/tauriApi.ts)
- **问题**：lib.rs L50-52 注册了 `start_proxy_cmd`、`stop_proxy_cmd`、`is_proxy_running_cmd` 三个命令，但 tauriApi.ts 中没有对应的 API 函数。
- **影响**：前端无法控制流量拦截代理的启停。
- **修复**：在 tauriApi.ts 添加三个代理控制函数。

#### H4：tray.rs 使用 unwrap() 可能导致 panic

- **文件**：[tray.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/tray.rs) L33
- **问题**：`app.default_window_icon().cloned().unwrap()` 在窗口图标未设置时会 panic，导致整个应用崩溃。
- **影响**：在图标资源缺失的边缘场景下应用无法启动。
- **修复**：改用 `unwrap_or_else` 提供默认图标或返回错误。

### 🟡 MEDIUM（5项）

#### M1：lib.rs setup 中使用 expect() 而非优雅降级

- **文件**：[lib.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/lib.rs) L25/26/28
- **问题**：`app_data_dir().expect()`、`create_dir_all().expect()`、`Database::open().expect()` 在失败时直接 panic，而非向用户展示错误信息。
- **影响**：如果 app_data_dir 不可访问或数据库文件损坏，应用直接崩溃无提示。
- **修复**：改用 `?` 传播错误并在 setup 中返回 Result。

#### M2：time crate 强制固定版本

- **文件**：[Cargo.toml](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/Cargo.toml) L32
- **问题**：`time = "=0.3.36"` 使用精确版本固定，可能与其他依赖（如 tauri-plugin-updater）的 time 版本要求冲突。
- **影响**：未来依赖更新时可能引发编译错误。
- **修复**：改为 `time = "0.3"` 或移除该行（让 Cargo 自动解析）。

#### M3：代码签名未配置

- **文件**：[tauri.conf.json](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/tauri.conf.json) L48-50
- **问题**：`certificateThumbprint: null`，`timestampUrl: ""`。
- **影响**：Windows SmartScreen 会警告未签名应用，影响用户体验和信任度。白皮书已标注"规划中"。
- **修复**：获取 EV 代码签名证书后配置（需外部资源）。

#### M4：CSP 允许 unsafe-inline 样式

- **文件**：[tauri.conf.json](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/tauri.conf.json) L28
- **问题**：CSP 中 `style-src 'self' 'unsafe-inline'` 允许内联样式，存在轻微 XSS 风险。
- **影响**：攻击者若能注入 HTML，可通过 style 属性进行 CSS 注入。
- **修复**：改用 CSS Modules 或 styled-components，移除 unsafe-inline（工作量较大，可延后）。

#### M5：白皮书内部基准测试数据来源不清

- **文件**：[白皮书.md](file:///e:/smallloong/XuanDun/docs/白皮书.md) 性能与基准测试章节
- **问题**：白皮书引用"内部基准测试 342条样本，17类攻击"的数据（99.6% 拒绝率、94.6% 通过率、4.99ms 延迟），但 `industry_benchmarks/results/` 下的实际结果文件显示的是 OWASP/raucle/内部扩展三个独立测试，没有对应"342条样本"的综合结果文件。
- **影响**：数据可追溯性不足。
- **修复**：要么生成综合结果文件，要么在白皮书中明确数据来源为三个测试的加权平均。

### 🟢 LOW（3项）

#### L1：db.rs 测试中大量 unwrap()

- **文件**：[db.rs](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src-tauri/src/db.rs) L294-368
- **问题**：测试代码中大量使用 `.unwrap()`。
- **影响**：测试失败时错误信息不够清晰，但不影响生产代码。
- **修复**：可改用 `expect("描述")` 提供更清晰的失败信息（可选）。

#### L2：前端 useEffect 依赖数组规范

- **文件**：[Dashboard.tsx](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src/pages/Dashboard.tsx)、[Agents.tsx](file:///e:/smallloong/XuanDun/desktop/xuandun-desktop/src/pages/Agents.tsx)
- **问题**：部分 useEffect 未提供完整的依赖数组。
- **影响**：可能导致闭包捕获旧值，但不影响基本功能。
- **修复**：添加 eslint-plugin-react-hooks 并修复警告（可选）。

#### L3：白皮书联系方式使用示例域名

- **文件**：[白皮书.md](file:///e:/smallloong/XuanDun/docs/白皮书.md) 末尾
- **问题**：`https://daoti.com` 和 `contact@daoti.com` 可能是示例值。
- **影响**：客户无法联系。
- **修复**：替换为真实联系方式。

---

## 三、已排除的误报

以下问题在初次审计中被 Explore agent 报告，但经手动核实**确认不存在**：

| 误报项 | 核实结果 |
|--------|---------|
| dynamic_shell.py 有 exec/eval/subprocess | ❌ 误报。exec/eval 仅出现在 benchmark/datasets.py 的**测试数据字符串**中，不是代码执行 |
| secure_strings.py 有 eval | ❌ 误报。文件中无 eval 调用 |
| reject_gate.py 有 SQL/pickle | ❌ 误报。无 SQL 操作，无 pickle，仅有 json.loads |
| ancient_mapper.py 有 pickle.loads | ❌ 误报。无 pickle 使用 |
| luoshu_mapper.py 使用 hash() | ❌ 误报。已修复为 hashlib.md5 |
| Agents.tsx 使用 dangerouslySetInnerHTML | ❌ 误报。前端完全未使用 |
| taskkill 命令注入 | ❌ 误报。pid 为 u32 整数，通过 to_string() 转换，无注入风险 |
| commands.rs protect 持锁发 HTTP | ❌ 误报。锁在代码块内释放（L75-78），HTTP 请求在锁外执行 |
| atlas_mapping.py 有 numpy 数组越界 | ❌ 误报。atlas_mapping.py 是纯字典映射，无 numpy 操作 |
| engine_flask.py 硬编码数据库连接 | ❌ 误报。使用 SQLite 本地文件，无数据库连接字符串 |

---

## 四、编译状态

### Rust 后端
- `cargo check`：✅ 通过（有少量 warning）
- `cargo test`：✅ 14个测试全部通过

### 前端
- `npm run build`：✅ 通过
- `npm test`：✅ 17个测试全部通过

### 待修复后重新编译
- H2（快照命令暴露）需要修改 Rust 代码后重新编译
- H3（代理 API 封装）需要修改前端代码后重新构建

---

## 五、修复优先级建议

| 优先级 | 问题编号 | 修复内容 | 预估工作量 |
|--------|---------|---------|-----------|
| P0 | H2 | 暴露快照命令到 Tauri + 前端 | 1小时 |
| P0 | H3 | 前端添加代理控制 API | 30分钟 |
| P0 | H4 | tray.rs unwrap 改为 unwrap_or_else | 10分钟 |
| P1 | M1 | lib.rs expect 改为 ? 传播 | 30分钟 |
| P1 | M2 | Cargo.toml time 版本约束放宽 | 5分钟 |
| P2 | M3 | 代码签名配置 | 需外部证书 |
| P2 | M4 | CSP 移除 unsafe-inline | 2小时 |
| P2 | M5 | 白皮书数据来源标注 | 30分钟 |
| P3 | L1-L3 | 测试/前端/文档微调 | 可选 |
