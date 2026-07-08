import '@testing-library/jest-dom';

const mockInvoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({
  invoke: mockInvoke,
}));

export { mockInvoke };
