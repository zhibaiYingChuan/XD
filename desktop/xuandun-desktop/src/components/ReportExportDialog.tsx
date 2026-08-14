import { useState, useCallback, useRef, useEffect } from 'react';
import { Download, Loader2, FileText, Calendar } from 'lucide-react';
import { api, WeeklyReportPreview } from '../services/tauriApi';

/**
 * ReportExportDialog — 周报导出对话框
 *
 * v1.3.4 P0-2.4 新增。提供日期范围选择、格式(CSV/JSON/HTML/MD)、模块选择及导出流程。
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
    // D-P1-5: 日期范围校验（空值/顺序颠倒/超长范围），避免生成空报告或引擎侧全表扫描
    if (!startDate || !endDate) {
      setError('请选择开始日期和结束日期');
      return;
    }
    if (startDate > endDate) {
      setError('开始日期不能晚于结束日期');
      return;
    }
    const rangeDays = Math.round((new Date(endDate).getTime() - new Date(startDate).getTime()) / 86400000);
    if (rangeDays > 366) {
      setError('日期范围不能超过 366 天，请缩小范围后重试');
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
      onShowMessage('success', `安全报告已导出到 ${savedPath}`);
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

  // ── 样式常量（对齐网关端深色主题） ──
  const s = {
    overlay: {
      position: 'fixed' as const,
      top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(0,0,0,0.6)',
      zIndex: 10000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    },
    dialog: {
      background: '#1e293b',
      border: '1px solid #475569',
      borderRadius: 12, padding: 24, maxWidth: 460, width: '92%',
      boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
      maxHeight: '85vh', overflow: 'auto',
    },
    title: { fontSize: 16, fontWeight: 600, color: '#e2e8f0', marginBottom: 20 },
    label: { display: 'block' as const, fontSize: 12, fontWeight: 500, color: '#94a3b8', marginBottom: 6 },
    input: {
      width: '100%', padding: '6px', borderRadius: 6,
      background: '#0f172a', color: '#e2e8f0',
      border: '1px solid #475569', fontSize: 13, outline: 'none',
    },
    btnPrimary: {
      padding: '8px 16px', borderRadius: 6, border: 'none', cursor: 'pointer',
      background: '#2563eb', color: '#fff', fontSize: 13, fontWeight: 500,
    },
    btnSecondary: {
      padding: '8px 16px', borderRadius: 6, border: '1px solid #475569', cursor: 'pointer',
      background: 'transparent', color: '#94a3b8', fontSize: 13,
    },
    chip: (active: boolean) => ({
      display: 'inline-flex', alignItems: 'center', gap: 4, padding: '6px 14px',
      borderRadius: 6, border: '1px solid', fontSize: 12, cursor: 'pointer', userSelect: 'none' as const,
      textTransform: 'uppercase' as const,
      background: active ? '#0c4a6e' : '#334155',
      color: active ? '#38bdf8' : '#94a3b8',
      borderColor: active ? '#38bdf8' : '#475569',
    }),
  };

  return (
    // D-P1-6: 生成/导出进行中禁止点击遮罩关闭（processingRef 同步锁），防止流程中断后状态悬挂
    <div style={s.overlay} onClick={() => { if (!processingRef.current) onClose(); }}>
      <div style={s.dialog} onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        {/* 标题栏 */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 style={{ fontSize: 16, fontWeight: 600, color: '#e2e8f0', margin: 0 }}>
            导出安全报告
          </h2>
          <button
            onClick={() => { if (!processingRef.current) onClose(); }}
            disabled={processingRef.current}
            title={processingRef.current ? '报告处理中，暂不能关闭' : '关闭'}
            style={{
              background: 'none', border: 'none', cursor: processingRef.current ? 'not-allowed' : 'pointer',
              color: '#94a3b8', padding: 0, fontSize: 18, opacity: processingRef.current ? 0.4 : 1,
            }}
            aria-label="关闭"
          >
            x
          </button>
        </div>

        {/* 状态：生成中 / 导出中 / 完成 */}
        {step === 'generating' && (
          <div style={{ textAlign: 'center', padding: '32px 0' }}>
            <Loader2 size={32} style={{ animation: 'spin 1s linear infinite', color: '#2563eb' }} />
            <p style={{ color: '#94a3b8', marginTop: 12 }}>正在生成报告...</p>
          </div>
        )}

        {step === 'exporting' && summary && (
          <div>
            {/* 生成成功摘要 */}
            <div style={{ background: '#0f172a', borderRadius: 8, padding: 12, marginBottom: 12, fontSize: 13 }}>
              <div style={{ color: '#4ade80', marginBottom: 6 }}>报告已生成</div>
              <div style={{ color: '#94a3b8' }}>检测总数: {summary.total_requests?.toLocaleString() ?? 0} | 拦截: {summary.total_blocked?.toLocaleString() ?? 0} | 拦截率: {summary.block_rate ?? 0}%</div>
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
            <FileText size={36} style={{ color: '#4ade80' }} />
            <p style={{ color: '#e2e8f0', marginTop: 12, fontWeight: 500 }}>
              安全报告已导出成功
            </p>
            <p style={{ color: '#94a3b8', fontSize: 13, marginTop: 4 }}>
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
                background: 'rgba(245,158,11,0.1)',
                border: '1px solid #f0ad4e',
                borderRadius: 6, padding: '8px 12px', marginBottom: 12,
                color: '#f0ad4e', fontSize: 12,
              }}>
                引擎未运行，无法生成报告。请先启动引擎。
              </div>
            )}

            {/* 错误提示 */}
            {error && (
              <div style={{
                background: 'rgba(220,53,69,0.1)', border: '1px solid #f87171',
                borderRadius: 6, padding: '8px 12px', marginBottom: 12,
                color: '#f87171', fontSize: 12,
              }}>
                {error}
              </div>
            )}

            {/* 快捷时间选择 */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
              {([
                { label: '今日', days: 0 },
                { label: '本周', days: 6 },
                { label: '本月', days: 29 },
              ] as const).map(({ label, days }) => (
                <button
                  key={label}
                  onClick={() => {
                    const end = new Date();
                    const start = new Date(end);
                    start.setDate(start.getDate() - days);
                    setStartDate(start.toISOString().slice(0, 10));
                    setEndDate(end.toISOString().slice(0, 10));
                  }}
                  style={{
                    padding: '4px 12px', borderRadius: 6, fontSize: 12,
                    border: '1px solid #475569',
                    background: '#334155',
                    color: '#94a3b8', cursor: 'pointer',
                  }}
                >
                  {label}
                </button>
              ))}
            </div>

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
