import '@testing-library/jest-dom';

// P0-FIX: Tauri桥接环境mock - invokeWithTimeout前置检查要求window.__TAURI_INTERNALS__存在
// 否则所有api调用在走到invoke前就会被reject，测试永远失败
if (typeof window !== 'undefined') {
  (window as any).__TAURI_INTERNALS__ = {
    invoke: vi.fn(),
  };
}

const mockInvoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({
  invoke: mockInvoke,
}));

export { mockInvoke };
