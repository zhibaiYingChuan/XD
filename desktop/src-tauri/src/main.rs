// ★★ Windows 上必须声明为 windows 子系统，否则会额外弹出一个
//   cmd 黑窗并把引擎日志刷在里面。
//
//   机制：MSVC 链接的可执行文件默认是 console 子系统，
//   双击运行时 Windows 就会为它分配一个控制台。GUI 程序不需要它，
//   而 `#![windows_subsystem = "windows"]` 告诉链接器不要分配。
//
//   ★ 这与引擎的 `--windows-console-mode=disable` 是**两件不同的事**：
//     · 本属性管**桌面端壳**（xuandun-personal.exe）自己要不要黑窗
//     · Nuitka 的 console-mode 管**引擎 exe**（被 shell 启动时）
//     两者都设了才彻底没有黑窗。只设后者，前者照样弹窗。
//
//   ★ 该属性只在 Windows 生效，Linux/macOS 上无害。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    xuandun_personal_lib::run()
}
