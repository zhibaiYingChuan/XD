// SPDX-License-Identifier: DaoTi-Research-1.0
// Copyright (c) 2026 独立研究者，知白
// 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
//
// 系统托盘 — 个人版唯一的「我被保护了」感知通道
//
// ── 为什么必须有托盘（产品定位：透明防火墙）─────────────────
// 玄盾的核心承诺是「响应侧自动拦截」，而用户对中转站返回了什么完全无感。
// 若用户关掉窗口进程就退出，防护会静默失效 —— 这是比「缺少可视化」严重得多的
// 问题：承诺在用户不知情时不再成立，且没有任何信号提示。
// 因此托盘必须承担三件事：
//     ① 常驻：窗口关闭 ≠ 应用退出，代理继续运行
//     ② 变色：防护状态实时可见（绿/黄/红/灰）
//     ③ 入口：托盘菜单可回到主窗口
//
// ── 变色采用两段式（避免单靠轮询导致「红色一直亮」）──────────
//   · 瞬时脉冲 —— Rust 侧检测到「新增一条阻断日志」时立即切红，
//     停留 PULSE_HOLD 后自动回落。这是「刚刚发生」的信号。
//   · 持续态   —— 前端轮询今日统计后主动下发，
//     表达「今天累计有几次危险」。
// 两者必须分开：若都用轮询，用户永远不知道红色是「刚发生」还是「今天有」。
//
// ── 图标为什么在 Rust 里画而不是读 PNG ──────────────────────
// Tauri 2 的 Image::from_bytes 解 PNG 需要额外 feature，
// 而托盘图标只有 4 个 16~64px 的盾牌，用像素光栅化即可，
// 零依赖、零资源文件、任意尺寸都清晰。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, Runtime,
};

/// 瞬时脉冲停留时长。红色停留过久会退化成常态噪声，失去「刚刚发生」含义。
const PULSE_HOLD_MS: u64 = 6_000;

/// 托盘 ID（Tauri 2 以 id 索引托盘实例）
pub const TRAY_ID: &str = "xuandun-tray";

/// 事件名：托盘状态变化时通知前端
pub const EVENT_TRAY_STATE: &str = "tray-state-changed";

// ══════════════════════════════════════════════════════════════
// 状态定义
// ══════════════════════════════════════════════════════════════

/// 托盘应显示的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrayState {
    /// 防护中，今日无危险
    Safe,
    /// 今日已发现可疑响应
    Suspect,
    /// 今日已阻断危险响应
    Danger,
    /// 防护已暂停或代理未运行
    Paused,
}

impl TrayState {
    fn parse(s: &str) -> TrayState {
        match s {
            "safe" => TrayState::Safe,
            "suspect" => TrayState::Suspect,
            "danger" => TrayState::Danger,
            _ => TrayState::Paused,
        }
    }

    /// 与前端 GuardState 对齐（protecting/learning → safe）
    fn label(self) -> &'static str {
        match self {
            TrayState::Safe => "防护中",
            TrayState::Suspect => "发现可疑响应",
            TrayState::Danger => "已拦截危险响应",
            TrayState::Paused => "防护未启用",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            TrayState::Safe => "safe",
            TrayState::Suspect => "suspect",
            TrayState::Danger => "danger",
            TrayState::Paused => "paused",
        }
    }

    fn rgb(self) -> (u8, u8, u8) {
        match self {
            // 与 styles.css 设计令牌一致
            TrayState::Safe => (0x00, 0xD4, 0xAA),
            TrayState::Suspect => (0xF5, 0xA6, 0x23),
            TrayState::Danger => (0xE5, 0x4D, 0x4D),
            // ★ 刻意比 styles.css 的 --xd-text-dim(#9AA4B8) 更深：
            //   托盘图标绘制在**系统任务栏**上，而任务栏主题不随本应用走 ——
            //   用户可能用亮色任务栏，深灰会几乎不可见。
            //   离线渲染实测（examples/render_tray.rs）：#8A8F98 在亮色底上
            //   对比度不足，降到 #5A6068 后四种状态在任何底色下都可辨认。
            //   「防护已停」恰恰是最需要被一眼看到的状态，不能靠悬停 tooltip 才发现。
            TrayState::Paused => (0x5A, 0x60, 0x68),
        }
    }
}

// ══════════════════════════════════════════════════════════════
// 盾牌光栅化
// ══════════════════════════════════════════════════════════════

/// 盾牌轮廓（基准 32×32 坐标系）。
///
/// 比例要点：上宽下窄，但**上半段接近竖直**，只在下 1/3 处收成尖点。
/// 若上半段也倾斜，缩小后视觉上会退化成倒三角/箭头，丢失盾牌语义。
#[rustfmt::skip]
const SHIELD: [(f32, f32); 7] = [
    (4.0,  3.5),   // 左上
    (28.0, 3.5),   // 右上
    (28.0, 15.0),  // 右侧竖直段底
    (24.0, 24.0),  // 右下收束
    (16.0, 29.5),  // 底部尖点
    (8.0,  24.0),  // 左下收束
    (4.0,  15.0),  // 左侧竖直段底
];

/// 射线法判断点是否在多边形内
fn point_in_poly(px: f32, py: f32) -> bool {
    let mut inside = false;
    let n = SHIELD.len();
    let mut j = n - 1;
    for i in 0..n {
        let (xi, yi) = SHIELD[i];
        let (xj, yj) = SHIELD[j];
        if (yi > py) != (yj > py) {
            let x_cross = (xj - xi) * (py - yi) / (yj - yi) + xi;
            if px < x_cross {
                inside = !inside;
            }
        }
        j = i;
    }
    inside
}

/// 生成 RGBA 盾牌图标。
///
/// 3×3 超采样抗锯齿：托盘实际显示 16~24px，直接硬边画会全是锯齿。
fn shield_image(size: u32, rgb: (u8, u8, u8)) -> Image<'static> {
    const SS: usize = 3;
    let mut buf = Vec::with_capacity((size * size * 4) as usize);

    for y in 0..size {
        for x in 0..size {
            let mut hits = 0u8;
            for sy in 0..SS {
                for sx in 0..SS {
                    // 采样点取像素中心偏移
                    let px = (x as f32) + (sx as f32 + 0.5) / SS as f32;
                    let py = (y as f32) + (sy as f32 + 0.5) / SS as f32;
                    // 32×32 基准 → 目标尺寸
                    let bx = px / size as f32 * 32.0;
                    let by = py / size as f32 * 32.0;
                    if point_in_poly(bx, by) {
                        hits += 1;
                    }
                }
            }
            let a = (hits as u16 * 255 / (SS * SS) as u16) as u8;
            buf.push(rgb.0);
            buf.push(rgb.1);
            buf.push(rgb.2);
            buf.push(a);
        }
    }

    Image::new_owned(buf, size, size)
}

// ══════════════════════════════════════════════════════════════
// 托盘控制器
// ══════════════════════════════════════════════════════════════

/// 托盘状态机。
///
/// 脉冲与持续态会互相覆盖，必须分别记住才能在脉冲结束后正确回落。
/// 用原子量而非 Mutex：全部字段都是平凡值，且要在 async 任务里访问。
#[derive(Default)]
pub struct TrayController {
    /// 持续态（前端轮询下发）
    steady: AtomicU64,
    /// 持续态补充说明
    steady_detail: parking_lot::Mutex<String>,
    /// 是否处于瞬时脉冲中
    pulsing: AtomicBool,
    /// 脉冲代际号：只有最新一次脉冲的回落任务才允许改状态
    pulse_gen: AtomicU64,
    /// 脉冲文案
    pulse_detail: parking_lot::Mutex<String>,
}

impl TrayController {
    /// 当前应显示的状态（脉冲优先）
    fn effective(&self) -> (TrayState, String) {
        if self.pulsing.load(Ordering::SeqCst) {
            let d = self.pulse_detail.lock().clone();
            return (TrayState::Danger, d);
        }
        let s = TrayState::parse(state_name(self.steady.load(Ordering::SeqCst)));
        let d = self.steady_detail.lock().clone();
        (s, d)
    }

    /// 前端下发持续态
    pub fn set_steady<R: Runtime>(&self, app: &AppHandle<R>, state: &str, detail: &str) {
        self.steady.store(state_code(state), Ordering::SeqCst);
        *self.steady_detail.lock() = detail.to_string();
        // 脉冲期间不改图标，避免把「刚刚发生」的信号冲掉
        if !self.pulsing.load(Ordering::SeqCst) {
            apply(app);
        }
    }

    /// 触发瞬时脉冲（刚刚发生了一次危险）
    pub fn pulse<R: Runtime>(&self, app: &AppHandle<R>, message: &str) {
        *self.pulse_detail.lock() = message.to_string();
        self.pulsing.store(true, Ordering::SeqCst);
        let gen = self.pulse_gen.fetch_add(1, Ordering::SeqCst) + 1;
        apply(app);

        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(PULSE_HOLD_MS)).await;
            let ctrl = handle.state::<TrayController>();
            // 期间又发生了新的脉冲 → 交给新的回落任务，旧的直接退出
            if ctrl.pulse_gen.load(Ordering::SeqCst) == gen {
                ctrl.pulsing.store(false, Ordering::SeqCst);
                apply(&handle);
            }
        });
    }

    /// 代理不可用时强制灰态（引擎启动失败、健康检查失败）
    pub fn force_paused<R: Runtime>(&self, app: &AppHandle<R>) {
        self.steady.store(3, Ordering::SeqCst);
        *self.steady_detail.lock() = "本地代理未运行".to_string();
        if !self.pulsing.load(Ordering::SeqCst) {
            apply(app);
        }
    }

    /// 持续态当前是否为灰（paused）。
    /// 供健康监控判断「该不该把托盘从灰切回正常」。
    pub fn is_paused(&self) -> bool {
        self.steady.load(Ordering::SeqCst) == 3
    }
}

fn state_code(s: &str) -> u64 {
    match s {
        "safe" => 0,
        "suspect" => 1,
        "danger" => 2,
        _ => 3,
    }
}

fn state_name(code: u64) -> &'static str {
    match code {
        0 => "safe",
        1 => "suspect",
        2 => "danger",
        _ => "paused",
    }
}

/// 把当前状态刷到托盘（图标 + tooltip）
fn apply<R: Runtime>(app: &AppHandle<R>) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    let (st, detail) = app.state::<TrayController>().effective();
    let _ = tray.set_icon(Some(shield_image(32, st.rgb())));
    let _ = tray.set_tooltip(Some(if detail.is_empty() {
        format!("道体·玄盾 个人版 — {}", st.label())
    } else {
        format!("道体·玄盾 个人版 — {}：{}", st.label(), detail)
    }));
    let _ = app.emit(EVENT_TRAY_STATE, st.as_str());
}

// ══════════════════════════════════════════════════════════════
// 构建
// ══════════════════════════════════════════════════════════════

/// 构建托盘：图标 + 菜单 + 交互
///
/// 刻意用非泛型 `AppHandle`（= Wry 运行时）：本应用只跑桌面环境，
/// 而泛型化后 `TrayIconBuilder` 内部要求 `Manager<Wry>`，
/// 泛型版本无法证明该约束成立，只会招来编译错误。
pub fn build(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "打开主窗口", true, None::<&str>)?;
    let pause = MenuItem::with_id(app, "pause", "暂停防护 30 分钟", true, None::<&str>)?;
    let resume = MenuItem::with_id(app, "resume", "恢复防护", true, None::<&str>)?;
    let logs = MenuItem::with_id(app, "logs", "打开安全日志", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "退出玄盾", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &show,
            &sep,
            &pause,
            &resume,
            &logs,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(shield_image(32, TrayState::Safe.rgb()))
        .tooltip("道体·玄盾 个人版 — 防护中")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            let id = event.id().as_ref();
            match id {
                "show" => show_main_window(app),
                "logs" => {
                    show_main_window(app);
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.eval("window.location.hash = '#/logs'");
                    }
                }
                "pause" => {
                    let app2 = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let _ = crate::post_local(&app2, "/api/pause", r#"{"duration_min":30}"#).await;
                    });
                }
                "resume" => {
                    let app2 = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let _ = crate::post_local(&app2, "/api/resume", "{}").await;
                    });
                }
                "quit" => {
                    // 真正退出：停引擎 + 退进程
                    crate::shutdown(app);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            // 左键单击 → 唤起主窗口（Windows 用户的主要入口）
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

/// 显示并聚焦主窗口
pub fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

// ══════════════════════════════════════════════════════════════
// Tauri 命令
// ══════════════════════════════════════════════════════════════

/// 前端下发托盘持续态
#[tauri::command]
pub fn set_tray_state(app: tauri::AppHandle, state: String, detail: String) {
    app.state::<TrayController>().set_steady(&app, &state, &detail);
}

/// 前端上报「刚刚发生了一次危险」（如阻断返回时）
#[tauri::command]
pub fn pulse_tray(app: tauri::AppHandle, message: String) {
    app.state::<TrayController>().pulse(&app, &message);
}

/// Rust 侧自检用：当前托盘状态
#[tauri::command]
pub fn get_tray_state(app: tauri::AppHandle) -> String {
    app.state::<TrayController>().effective().0.as_str().to_string()
}

// ══════════════════════════════════════════════════════════════
// 测试
// ══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// 取缓冲中不透明像素的主色。
    ///
    /// 只统计 alpha>200 的像素：抗锯齿边缘是半透明的过渡色，
    /// 混进来会让断言在边缘色与主色之间摇摆。
    fn dominant_rgb(buf: &[u8]) -> (u8, u8, u8) {
        let mut best = (0usize, (0u8, 0u8, 0u8));
        for px in buf.chunks_exact(4) {
            if px[3] > 200 {
                let c = (px[0], px[1], px[2]);
                // 绿色分量最高者即盾牌主色。
                // 灰态 #5A6068 的绿分量（96）虽是四态中最低，
                // 但每张图只渲染一种状态，组内比较无意义。
                let score = c.1 as usize;
                if score > best.0 {
                    best = (score, c);
                }
            }
        }
        best.1
    }

    fn opaque_count(buf: &[u8]) -> usize {
        buf.chunks_exact(4).filter(|px| px[3] > 200).count()
    }

    /// 缓冲长度必须严格等于 size*size*4。
    ///
    /// ★ 这是历史上真实踩过的坑：tauri 的 `Image::new(rgba, w, h)` 期望
    ///   原始 RGBA 像素，而曾误传 PNG 编码字节 —— 32² 的 raw RGBA 需 4096B，
    ///   PNG 文件却只有 2KB 量级，长度不匹配会让托盘显示未定义内容。
    ///   这个断言把「长度不符」变成编译期可见的失败，而非肉眼才能发现。
    #[test]
    fn image_buffer_length_matches_size() {
        for size in [16u32, 32, 64] {
            let img = shield_image(size, (0x00, 0xD4, 0xAA));
            assert_eq!(
                img.rgba().len(),
                size as usize * size as usize * 4,
                "{size}×{size} 缓冲长度与尺寸不符"
            );
        }
    }

    /// 四态必须产出四种**互不相同**的颜色，且与设计令牌一致。
    ///
    /// ★ 这是托盘视觉验证的本质：托盘只有这一个像素通道，
    ///   颜色错了用户无从察觉（tooltip 文字仍会变，但没人会悬停确认）。
    ///   Win11 通知区无法直读像素（ToolbarWindow32 结构与 Win10 不同），
    ///   但颜色在这里就已经完全确定 —— 改这一个函数就等于改用户看到的图标。
    #[test]
    fn four_states_render_distinct_colors() {
        let expected = [
            (TrayState::Safe, (0x00u8, 0xD4, 0xAA)),
            (TrayState::Suspect, (0xF5, 0xA6, 0x23)),
            (TrayState::Danger, (0xE5, 0x4D, 0x4D)),
            (TrayState::Paused, (0x5A, 0x60, 0x68)),
        ];

        let mut seen: Vec<(u8, u8, u8)> = Vec::new();
        for (state, want) in expected {
            let img = shield_image(32, state.rgb());
            let got = dominant_rgb(img.rgba());
            assert_eq!(got, want, "{} 态渲染颜色不符", state.as_str());
            assert!(opaque_count(img.rgba()) > 200, "{} 态盾牌几乎不可见", state.as_str());
            assert!(
                !seen.contains(&got),
                "{} 态与前面某态撞色，托盘无法区分",
                state.as_str()
            );
            seen.push(got);
        }
    }

    /// 盾牌形状必须真的是盾牌，而不是退化成方块或三角。
    ///
    /// 判据：四角透明（否则是方块）、上宽下窄（否则不是盾形）、
    /// 中心不透明（否则轮廓自相矛盾）。
    #[test]
    fn shield_shape_is_legible() {
        let img = shield_image(32, (0x00, 0xD4, 0xAA));
        let px = |x: usize, y: usize| -> u8 { img.rgba()[(y * 32 + x) * 4 + 3] };

        // 四角必须透明
        for (x, y) in [(0usize, 0usize), (31, 0), (0, 31), (31, 31)] {
            assert_eq!(px(x, y), 0, "({x},{y}) 不透明，轮廓退化成方块");
        }
        // 几何中心必须不透明
        assert!(px(16, 14) > 200, "中心透明，轮廓自相矛盾");
        // 上部宽度 > 下部宽度（盾牌语义的关键特征）
        let width_at = |y: usize| -> usize {
            (0..32).filter(|x| px(*x, y) > 200).count()
        };
        assert!(width_at(8) > width_at(24), "上窄下宽，不是盾牌形状");
    }

    /// 非法状态名必须降级为灰态，绝不能静默显示绿色。
    ///
    /// ★ 安全含义：绿色意味着「防护中」。若未知状态被当成 safe，
    ///   用户会在防护已停时看到「一切正常」—— 这是最危险的一种错。
    #[test]
    fn unknown_state_degrades_to_gray() {
        assert_eq!(TrayState::parse("bogus_value").as_str(), "paused");
        assert_eq!(TrayState::parse("").as_str(), "paused");
        assert_eq!(state_name(state_code("bogus_value")), "paused");
    }
}
