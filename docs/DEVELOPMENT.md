# 个人版开发指南

> 内部文档，不对外发布。面向用户的说明见根目录 `README.md`。

## 一、开发环境

```bash
cd personal
pip install -e ".[dev]"
```

依赖已随仓库入库（护栏层内置于 `src/daoti_xuandun/`），不依赖企业版 SDK。

### 桌面端

```bash
cd personal/desktop
npm install
npm run tauri dev
```

### 单独启动引擎

```bash
cd personal
python -m daoti_xuandun_personal.proxy.app --port 18765
```

---

## 二、验证

### 全量测试

```bash
cd personal
python -m pytest tests -q              # 全量（约 700 项，以实际输出为准）
```

> 不要在这里写死一个精确数字：测试增加时它必然过期，
> 而过期的文档会让"跑一下看看"的人误以为自己跑漏了。

### 测试资产口径（哪些判据算合格）

原则：**判据优先锁「契约与失败行为」，而不是锁源码文本。**

| 类别 | 是否入库 | 说明 |
|---|---|---|
| 跨语言契约 | 必须 | 环境变量名、超时顺序、状态码、字段名。这类漂移两边各自都"正常"，只有联调才暴露 |
| 失败路径的可见反馈 | 必须 | 「加载失败」不能与「没有数据」同屏；破坏性操作要有在飞锁 |
| 派生数据与事实层一致 | 必须 | 删日志后统计要跟着重算，否则数字会凭空停在旧值 |
| 读源码文本 / 断言文案字面量 | 谨慎 | 重构即误报。只允许用于"结构必须不存在"这类无法从行为观察的判据，且要写清为什么只能静态断言 |
| 攻击样本、误报阈值 | 禁止 | 随仓库分发等于公开说明"哪里容易误报、边界在哪" |

### 分类验证

```bash
# 降级可见性自检
python tests/check_degradation.py

# 防护能力实测（三层管道 + 34 个真实攻击样本）
python tests/probe_capability.py
# 请求侧 12（8 正例 + 4 负例）· 响应侧 20（12 正例 + 8 负例）· 占位符 2
# 含 Unicode 隐写四类（Tags 块 / 变体选择符 / 零宽二进制 / 同形异义字）
# 负例专门覆盖俄语正文、单个 Tags 语言标签、emoji —— 误报同样是 bug

# Phase 7 专项验收（需先启动引擎并指定端口 18799）
python tests/verify_phase7.py
```

### 桌面端端到端回归

```bash
# 终端 1：启动桌面端（debug 构建自动开 CDP 9224）
cd personal/desktop/src-tauri && cargo run

# 终端 2
cd personal
python tests/cdp_desktop_regression.py
```

### 其他检查

```bash
cd desktop
npx tsc --noEmit                       # 前端类型检查
npm run build                          # 前端构建
cd src-tauri && cargo check             # Rust 编译检查
cargo test --lib                        # 机器码哈希 / 时钟回拨（8 项）
```

---

## 三、托盘图标视觉验证

Win11 通知区无法直读像素 —— `ToolbarWindow32` 结构与 Win10 不同，
`FindWindowEx` 返回 0、UI Automation 扫到的是 Edge 工具栏。改为离线渲染出图肉眼确认：

```bash
cd desktop/src-tauri
cargo run --example render_tray -- <输出目录>   # 输出 16/24/32px × 四态共 12 张 PNG
```

托盘图标由 `tray.rs` 的 `shield_image()` 程序化光栅化（3×3 超采样抗锯齿），
颜色即设计令牌：safe `#00D4AA` / suspect `#F5A623` / danger `#E54D4D` / paused `#5A6068`。

> 灰态刻意比界面令牌 `--xd-text-dim(#9AA4B8)` 更深：托盘绘制在**系统任务栏**上，
> 而任务栏主题不随本应用走，用户可能用亮色任务栏。离线渲染实测 `#8A8F98` 在亮色底上
> 几乎不可见，而「防护已停」恰恰是最需要被一眼看到的状态。

---

## 四、打包与发版

### 发版链路

推送 `v*` tag 即触发 `.github/workflows/release.yml`：四个平台并行构建 → VirusTotal 扫描 → 生成 `latest.json` → 创建 Release。
版本号唯一来源是 `desktop/src-tauri/Cargo.toml`，其余位置由 `.github/scripts/sync_version.py` 派生，CI 用 `--check` 拦截不一致。

### 本地构建

```bash
cd personal/desktop

# ① 编译 Python 引擎（Nuitka standalone，约 10 min）
python build_engine.py
#    产物：src-tauri/resources/engine/

# ② 打包安装包
npx tauri build
```

**为何用 Nuitka `--standalone` 而非 `--onefile`**：
onefile 会自解压到临时目录，该行为特征被杀毒软件判定为 dropper —— 企业版 v1.3.1 曾因此被火绒误报 `Trojan/Intercept.a`。

`createUpdaterArtifacts` **只在 CI 配置** `tauri.updater.conf.json` 里开启：本地构建没有签名私钥，写进主配置会让日常 `tauri build` 直接失败。

### 三平台产物

| 平台 | 安装包 | 自动更新包 | 状态 |
|---|---|---|---|
| Windows x64 | NSIS `.exe` | 同 `.exe` + `.exe.sig` | 已实机验证 |
| macOS arm64 | `.dmg` | `.app.tar.gz` + `.sig` | 已接入 CI |
| Linux x86_64 | `.deb`（主）/ `.AppImage` | `.AppImage` + `.sig` | 已接入 CI |

macOS 分发需 Apple 签名与公证，未配置证书时产出的 `.dmg` 会触发 Gatekeeper 警告。

### 自动更新（三条必须守住的规则）

1. **私钥必须与公钥成对**。`check_signing_key.py` 在构建前用私钥签一个探测文件、比对 minisign key id；错配时构建照样成功，但所有客户端更新都会验签失败。
2. **`.sig` 是双层 base64**。tauri-cli 2.11.5 把整个 minisign 签名文件再编码一次写进 `.sig`，解析时要先解外层、再取其中 74 字节的签名，否则会把文本当成签名。
3. **发布资产名必须是 ASCII**。GitHub 会静默剥掉资产名里的中文（`道体·玄盾 个人版_...exe` → `_...exe`），而 `latest.json` 写的是原名，更新 URL 直接 404 —— 表现为「发版全绿、更新清单也在，客户端却永远升不了级」。所以发布前统一改名为 `xuandun-personal_<版本>_<平台>.<扩展名>`，清单与校验值都从同一个 `dist/` 目录生成。

---

## 五、代理端口约定（★ 三方一致性）

| 环节 | 取值来源 |
|---|---|
| Rust 桌面端 | 进程启动时读 `config.json` 的 `server.port`，存 `OnceLock` 锁定 |
| 引擎实际监听 | 由 Rust 传的 `--port` 决定（`proxy/app.py` 的 `run()` 中 `args.port` 优先于配置） |
| 界面展示 | `get_active_port()` 返回**实际运行**端口，非配置值 |

端口在进程内**不热重读**：用户改端口后配置立即落盘但引擎仍听旧端口，
若此时改连新端口将彻底失联（连「改回旧端口」的自救都做不到）。改端口后须重启应用。

### 一个已踩过的坑

Rust 侧解析 `config.json` 的 `server.port` 时**只接受 JSON 数字类型** ——
若写成 `"port": "19999"`（字符串），Python 侧 `ServerConfig(**raw["server"])`
会抛 `TypeError` 并回退整套默认配置（端口 18765），
而 Rust 若用字符串扫描提取数字会得到 19999，两侧失联且无从恢复。

实测结论：安装后 CDP 读到的 `get_active_port()` 与引擎 `--port` 一致，均为 18765。
