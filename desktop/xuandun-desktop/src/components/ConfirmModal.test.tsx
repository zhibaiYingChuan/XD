import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ConfirmModal, useConfirmModal } from './ConfirmModal';

describe('ConfirmModal', () => {
  describe('渲染', () => {
    it('open=true 时渲染弹窗', () => {
      render(
        <ConfirmModal open={true} message="确认删除？" onConfirm={() => {}} onCancel={() => {}} />
      );
      expect(screen.getByText('确认删除？')).toBeInTheDocument();
      expect(screen.getByText('确认')).toBeInTheDocument();
      expect(screen.getByText('取消')).toBeInTheDocument();
    });

    it('open=false 时返回 null', () => {
      const { container } = render(
        <ConfirmModal open={false} message="确认删除？" onConfirm={() => {}} onCancel={() => {}} />
      );
      expect(container.innerHTML).toBe('');
    });
  });

  describe('交互', () => {
    it('点击确认按钮触发 onConfirm', () => {
      const onConfirm = vi.fn();
      const onCancel = vi.fn();
      render(
        <ConfirmModal open={true} message="确认删除？" onConfirm={onConfirm} onCancel={onCancel} />
      );
      fireEvent.click(screen.getByText('确认'));
      expect(onConfirm).toHaveBeenCalledTimes(1);
      expect(onCancel).not.toHaveBeenCalled();
    });

    it('点击取消按钮触发 onCancel', () => {
      const onConfirm = vi.fn();
      const onCancel = vi.fn();
      render(
        <ConfirmModal open={true} message="确认删除？" onConfirm={onConfirm} onCancel={onCancel} />
      );
      fireEvent.click(screen.getByText('取消'));
      expect(onCancel).toHaveBeenCalledTimes(1);
      expect(onConfirm).not.toHaveBeenCalled();
    });

    it('点击遮罩层触发 onCancel', () => {
      const onCancel = vi.fn();
      const { container } = render(
        <ConfirmModal open={true} message="确认删除？" onConfirm={() => {}} onCancel={onCancel} />
      );
      const overlay = container.firstElementChild!;
      fireEvent.click(overlay);
      expect(onCancel).toHaveBeenCalledTimes(1);
    });

    it('按 ESC 键触发 onCancel', () => {
      const onCancel = vi.fn();
      render(
        <ConfirmModal open={true} message="确认删除？" onConfirm={() => {}} onCancel={onCancel} />
      );
      fireEvent.keyDown(window, { key: 'Escape' });
      expect(onCancel).toHaveBeenCalledTimes(1);
    });

    it('弹窗关闭时 ESC 键不触发 onCancel', () => {
      const onCancel = vi.fn();
      render(
        <ConfirmModal open={false} message="确认删除？" onConfirm={() => {}} onCancel={onCancel} />
      );
      fireEvent.keyDown(window, { key: 'Escape' });
      expect(onCancel).not.toHaveBeenCalled();
    });
  });
});

describe('useConfirmModal 队列化', () => {
  it('队列化：多次 confirm 调用逐个显示', async () => {
    function QueueTest() {
      const { modalProps, confirm } = useConfirmModal();
      return (
        <div>
          <button
            data-testid="multi"
            onClick={async () => {
              const r1 = await confirm('请求1');
              const r2 = await confirm('请求2');
              document.body.setAttribute('data-r1', String(r1));
              document.body.setAttribute('data-r2', String(r2));
            }}
          >
            多请求
          </button>
          <ConfirmModal {...modalProps} />
        </div>
      );
    }
    render(<QueueTest />);
    expect(screen.getByTestId('multi')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('multi'));

    // 第一个弹窗应该显示
    expect(screen.getByText('请求1')).toBeInTheDocument();
    expect(screen.queryByText('请求2')).not.toBeInTheDocument();

    // 确认第一个
    fireEvent.click(screen.getByText('确认'));
    // 等待状态更新后，第二个弹窗显示
    expect(await screen.findByText('请求2')).toBeInTheDocument();
    expect(screen.queryByText('请求1')).not.toBeInTheDocument();

    // 取消第二个
    fireEvent.click(screen.getByText('取消'));
    expect(screen.queryByText('请求2')).not.toBeInTheDocument();
  });

  it('取消弹窗返回 false', async () => {
    function CancelTest() {
      const { modalProps, confirm } = useConfirmModal();
      return (
        <div>
          <button
            data-testid="cancel-test"
            onClick={async () => {
              const r = await confirm('取消测试');
              document.body.setAttribute('data-cancel-result', String(r));
            }}
          >
            取消测试
          </button>
          <ConfirmModal {...modalProps} />
        </div>
      );
    }
    render(<CancelTest />);
    expect(screen.getByTestId('cancel-test')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('cancel-test'));

    // 弹窗消息和按钮文本都包含"取消测试"，用 data-testid 定位按钮
    expect(screen.getByTestId('cancel-test')).toBeInTheDocument();
    fireEvent.click(screen.getByText('取消'));

    await vi.waitFor(() => {
      expect(document.body.getAttribute('data-cancel-result')).toBe('false');
    });
  });

  it('组件卸载时清理队列中未处理的 Promise', async () => {
    function UnmountTest() {
      const { modalProps, confirm } = useConfirmModal();
      return (
        <div>
          <button
            data-testid="unmount"
            onClick={async () => {
              const r = await confirm('待清理');
              document.body.setAttribute('data-cleaned', String(r));
            }}
          >
            触发
          </button>
          <ConfirmModal {...modalProps} />
        </div>
      );
    }
    const { unmount } = render(<UnmountTest />);
    expect(screen.getByTestId('unmount')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('unmount'));

    expect(screen.getByText('待清理')).toBeInTheDocument();

    unmount();

    await vi.waitFor(() => {
      expect(document.body.getAttribute('data-cleaned')).toBe('false');
    });
  });
});