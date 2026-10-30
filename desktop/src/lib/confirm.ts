/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   应用内二次确认框。

   为什么不用 window.confirm
   ────────────────────────────────────────────────────────────
   ① tauri-plugin-dialog 2.7.2 把 window.confirm 改写成 async 函数
      （返回 Promise），而调用处写的是「取反即提前返回」的写法——
      Promise 恒为真，于是「用户还没点确定，删除就已经执行了」。
   ② 更要命的是，2.7.2 里 dialog 插件只注册了 message / open / save
      三个命令，`allow-confirm` 只是 `allow-message` 的废弃别名，
      根本没有命令去授权 `plugin:dialog|confirm` —— 运行时直接
      `Command plugin:dialog|confirm not allowed by ACL`。

   结论：原生 confirm 在这个版本上不可用。这里用应用内模态框实现，
   行为与原生一致：返回 Promise<boolean>，Esc / 点遮罩 = 取消，
   Enter = 确定，同一时刻只允许一个确认框。
*/

let active: ((v: boolean) => void) | null = null;

/**
 * 弹出确认框。确定返回 true，取消 / Esc / 点遮罩返回 false。
 *
 * ★ 调用处必须 await：
 *   `if (!(await confirmDialog('...'))) return;`
 */
export function confirmDialog(message: string): Promise<boolean> {
  // 上一个还没答复就被新的顶掉：按「取消」处理，避免悬挂的 Promise
  if (active) {
    active(false);
    active = null;
  }

  return new Promise<boolean>((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.setAttribute('data-xd-confirm', '1');

    const box = document.createElement('div');
    box.className = 'modal';
    box.setAttribute('role', 'dialog');
    box.setAttribute('aria-modal', 'true');
    box.setAttribute('aria-label', '请确认');

    const text = document.createElement('div');
    text.className = 'modal-text';
    // pre-line：把调用方文案里的 \n 原样保留成换行
    text.style.whiteSpace = 'pre-line';
    text.textContent = message;

    const actions = document.createElement('div');
    actions.className = 'modal-actions';

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn ghost';
    cancelBtn.textContent = '取消';
    cancelBtn.setAttribute('data-xd-confirm-cancel', '1');

    const okBtn = document.createElement('button');
    okBtn.className = 'btn danger';
    okBtn.textContent = '确定';
    okBtn.setAttribute('data-xd-confirm-ok', '1');

    let done = false;
    const close = (v: boolean) => {
      if (done) return;
      done = true;
      active = null;
      document.removeEventListener('keydown', onKey, true);
      overlay.remove();
      resolve(v);
    };
    active = close;

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();   // 不让日志抽屉的 Esc 同时把抽屉关掉
        close(false);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        e.stopPropagation();
        close(true);
      }
    };

    cancelBtn.addEventListener('click', () => close(false));
    okBtn.addEventListener('click', () => close(true));
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) close(false);
    });

    actions.append(cancelBtn, okBtn);
    box.append(text, actions);
    overlay.append(box);
    document.body.append(overlay);

    document.addEventListener('keydown', onKey, true);
    // 焦点放到「取消」上：确认框默认不替用户做破坏性决定
    cancelBtn.focus();
  });
}
