import { useState, useCallback, useRef, useEffect } from 'react';
import { X, Download, Loader2, FileText, Calendar } from 'lucide-react';
import { api, WeeklyReportPreview } from '../services/tauriApi';

/**
 * ReportExportDialog — 周报导出对话框
 *
 * v1.3.4 P0-2.4 新增。提供日期范围选择、格式(HTML/PDF)、模块选择及导出流程。
 * 引擎 /report/weekly 端点 + Rust export_report_file 命令完成端到端导出。
 */

type ReportFormat = 'csv' | 'json' | 'html' | 'md';
type ReportSection = 'summary' | 'trend' | 'distribution' | 'detail' | 'top_sources';

interface ReportExportDialogProps {
  open: boolean;
  onClose: () => void;
  engineRunning: boolean;
  onShowMessage: (type: 'success' | 'error', text: string) => void;
}

/** 默认日期范围：最近 7 天 */
function defaultDateRange(): { start: string; end: string } {
  const end = new Date();
  const start = new Date(end);
  start.setDate(start.getDate() - 6);
  return {
    start: start.toISOString().slice(0, 10),
    end: end.toISOString().slice(0, 10),
  };
}

export default function ReportExportDialog({
  open,
  onClose,
  engineRunning,
  onShowMessage,
}: ReportExportDialogProps) {
  // ── 表单状态 ──
  const { start, end } = defaultDateRange();
  const [startDate, setStartDate] = useState(start);
  const [endDate, setEndDate] = useState(end);
  const [format, setFormat] = useState<ReportFormat>('csv');
  const [sections, setSections] = useState<ReportSection[]>([
    'summary', 'trend', 'distribution', 'detail', 'top_sources',
  ]);

  // ── 流程状态 ──
  const [step, setStep] = useState<'form' | 'generating' | 'exporting' | 'done'>('form');
  const [summary, setSummary] = useState<WeeklyReportPreview | null>(null);
  const [filePath, setFilePath] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  // ── 防穿透锁 ──
  const processingRef = useRef(false);

  // 重置状态（open 切换时）
  useEffect(() => {
    if (open) {
      const d = defaultDateRange();
      setStartDate(d.start);
      setEndDate(d.end);
      setFormat('csv');
      setSections(['summary', 'trend', 'distribution', 'detail', 'top_sources']);
      setStep('form');
      setSummary(null);
      setFilePath('');
      setError(null);
      processingRef.current = false;
    }
  }, [open]);

  // ── 模块勾选 ──
  const toggleSection = (s: ReportSection) => {
    setSections((prev) =>
      prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]
    );
  };

  const sectionLabels: Record<ReportSection, string> = {
    summary: '概览',
    trend: '趋势图',
    distribution: '攻击分布',
    detail: '每日明细',
    top_sources: '攻击来源 Top10',
  };

  // ── ESC 关闭 ──
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !processingRef.current) {
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  // ── 生成报告 ──
  const handleGenerate = useCallback(async () => {
    if (processingRef.current) return;
    if (sections.length === 0) {
      setError('至少选择一个报告模块');
      return;
    }
    processingRef.current = true;
    setStep('generating');
    setError(null);
    try {
      const result = await api.generateWeeklyReport({
        start_date: startDate,
        end_date: endDate,
        format,
        sections,
      });
      setFilePath(result.file_path);
      setSummary(result.summary);
      setStep('exporting');
      onShowMessage('success', `报告已生成（${(result.file_size / 1024).toFixed(1)} KB）`);
    } catch (e: any) {
      setError(String(e?.message || e));
      setStep('form');
      onShowMessage('error', `报告生成失败：${String(e?.message || e)}`);
    } finally {
      processingRef.current = false;
    }
  }, [startDate, endDate, format, sections, onShowMessage]);

  // ── 导出到文件 ──
  const handleExport = useCallback(async () => {
    if (processingRef.current || !filePath) return;
    processingRef.current = true;
    try {
      const ext = format === 'csv' ? 'csv' : format === 'json' ? 'json' : format === 'md' ? 'md' : 'html';
      const suggested = `xuandun_report_${endDate}.${ext}`;
      // v1.3.4 修复: exportReportFile 内部打开 save dialog，用户选路径后写入
      const savedPath = await api.exportReportFile(filePath, suggested);
      setStep('done');
      onShowMessage('success', `周报已导出到 ${savedPath}`);
    } catch (e: any) {
      setError(String(e?.message || e));
      // 用户取消 save dialog 不算错误，不弹错误提示
      if (!String(e?.message || e).includes('取消')) {
        onShowMessage('error', `导出失败：${String(e?.message || e)}`);
      }
    } finally {
      processingRef.current = false;
    }
  }, [filePath, format, endDate, onShowMessage]);

  if (!open) return null;

  // ── 样式常量 ──
  const s = {
    overlay: {
      position: 'fixed' as const,
      top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(0,0,0,0.5)',
      zIndex: 10000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    },
    dialog: {
      background: 'var(--bg-primary, #1a1a2e)',
      border: '1px solid var(--border-color, #333)',
      borderRadius: 12, padding: 24, maxWidth: 520, width: '92%',
      boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
      maxHeight: '85vh', overflow: 'auto',
    },
    title: { fontSize: 16, fontWeight: 600, color: 'var(--text-primary, #e0e0e0)', marginBottom: 20 },
    label: { display: 'block' as const, fontSize: 13, fontWeight: 500, color: 'var(--text-secondary, #a0a0a0)', marginBottom: 6 },
    input: {
      width: '100%', padding: '8px 12px', borderRadius: 6,
      background: 'var(--bg-secondary, #16213e)', color: 'var(--text-primary, #e0e0e0)',
      border: '1px solid var(--border-color, #333)', fontSize: 13, outline: 'none',
    },
    btnPrimary: {
      padding: '8px 20px', borderRadius: 6, border: 'none', cursor: 'pointer',
      background: 'var(--btn-primary-bg, #3b82f6)', color: '#fff', fontSize: 13, fontWeight: 500,
    },
    btnSecondary: {
      padding: '8px 20px', borderRadius: 6, border: '1px solid var(--border-color, #333)', cursor: 'pointer',
      background: 'transparent', color: 'var(--text-secondary, #a0a0a0)', fontSize: 13,
    },
    chip: (active: boolean) => ({
      display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 10px',
      borderRadius: 6, border: '1px solid', fontSize: 12, cursor: 'pointer', userSelect: 'none' as const,
      background: active ? 'var(--btn-primary-bg, #3b82f6)' : 'transparent',
      color: active ? '#fff' : 'var(--text-secondary, #a0a0a0)',
      borderColor: active ? 'var(--btn-primary-bg, #3b82f6)' : 'var(--border-color, #333)',
    }),
  };

  return (
    <div style={s.overlay} onClick={onClose}>
      <div style={s.dialog} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        {/* 标题栏 */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary, #e0e0e0)', margin: 0 }}>
            导出安全周报
          </h2>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', padding: 0 }}
            aria-label="关闭"
          >
            <X size={18} strokeWidth={1.5} />
          </button>
        </div>

        {/* 状态：生成中 / 导出中 / 完成 */}
        {step === 'generating' && (
          <div style={{ textAlign: 'center', padding: '32px 0' }}>
            <Loader2 size={32} style={{ animation: 'spin 1s linear infinite', color: 'var(--btn-primary-bg, #3b82f6)' }} />
            <p style={{ color: 'var(--text-secondary, #a0a0a0)', marginTop: 12 }}>正在生成报告...</p>
          </div>
        )}

        {step === 'exporting' && summary && (
          <div>
            {/* 生成成功摘要 */}
            <div style={{ background: 'var(--bg-secondary, #16213e)', borderRadius: 8, padding: 12, marginBottom: 16 }}>
              <div style={{ display: 'flex', gap: 16 }}>
                <div>
                  <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)' }}>
                    {summary.total_requests?.toLocaleString() ?? 0}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>检测总数</div>
                </div>
                <div>
                  <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)' }}>
                    {summary.total_blocked?.toLocaleString() ?? 0}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>拦截次数</div>
                </div>
                <div>
                  <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)' }}>
                    {summary.block_rate ?? 0}%
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>拦截率</div>
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button
                style={s.btnSecondary}
                onClick={() => { setStep('form'); setSummary(null); }}
              >
                重新生成
              </button>
              <button style={s.btnPrimary} onClick={handleExport}>
                <Download size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} />
                导出{format.toUpperCase()}
              </button>
            </div>
          </div>
        )}

        {step === 'done' && (
          <div style={{ textAlign: 'center', padding: '24px 0' }}>
            <FileText size={36} style={{ color: 'var(--success, #22c55e)' }} />
            <p style={{ color: 'var(--text-primary, #e0e0e0)', marginTop: 12, fontWeight: 500 }}>
              周报已导出成功
            </p>
            <p style={{ color: 'var(--text-secondary, #a0a0a0)', fontSize: 13, marginTop: 4 }}>
              文件保存至指定位置，可在文件管理器中查看
            </p>
            <div style={{ marginTop: 16 }}>
              <button style={s.btnPrimary} onClick={onClose}>确定</button>
            </div>
          </div>
        )}

        {/* 表单 */}
        {step === 'form' && (
          <>
            {/* 引擎未运行提示 */}
            {!engineRunning && (
              <div style={{
                background: 'var(--bg-warning, rgba(245,158,11,0.1))',
                border: '1px solid var(--warning, #f0ad4e)',
                borderRadius: 6, padding: '8px 12px', marginBottom: 16,
                color: 'var(--warning, #f0ad4e)', fontSize: 12,
              }}>
                引擎未运行，无法生成报告。请先启动引擎。
              </div>
            )}

            {/* 错误提示 */}
            {error && (
              <div style={{
                background: 'rgba(220,53,69,0.1)', border: '1px solid #dc3545',
                borderRadius: 6, padding: '8px 12px', marginBottom: 16,
                color: '#dc3545', fontSize: 12,
              }}>
                {error}
              </div>
            )}

            {/* 日期范围 */}
            <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
              <div style={{ flex: 1 }}>
                <label style={s.label}><Calendar size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} />开始日期</label>
                <input
                  type="date"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  style={s.input}
                />
              </div>
              <div style={{ flex: 1 }}>
                <label style={s.label}><Calendar size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} />结束日期</label>
                <input
                  type="date"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  style={s.input}
                />
              </div>
            </div>

            {/* 导出格式 */}
            <div style={{ marginBottom: 16 }}>
              <label style={s.label}>导出格式</label>
              <div style={{ display: 'flex', gap: 8 }}>
                {(['csv', 'json', 'html', 'md'] as ReportFormat[]).map((f) => (
                  <button
                    key={f}
                    style={s.chip(format === f)}
                    onClick={() => setFormat(f)}
                  >
                    {f.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {/* 报告模块 */}
            <div style={{ marginBottom: 20 }}>
              <label style={s.label}>报告模块</label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {(Object.keys(sectionLabels) as ReportSection[]).map((sec) => (
                  <button
                    key={sec}
                    style={s.chip(sections.includes(sec))}
                    onClick={() => toggleSection(sec)}
                  >
                    {sectionLabels[sec]}
                  </button>
                ))}
              </div>
            </div>

            {/* 底部按钮 */}
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button style={s.btnSecondary} onClick={onClose}>
                取消
              </button>
              <button
                style={{
                  ...s.btnPrimary,
                  opacity: !engineRunning ? 0.5 : 1,
                  cursor: !engineRunning ? 'not-allowed' : 'pointer',
                }}
                disabled={!engineRunning}
                onClick={handleGenerate}
              >
                生成报告
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
