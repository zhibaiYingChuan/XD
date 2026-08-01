import { useState, useEffect, useCallback } from 'react';
import { AlertTriangle } from 'lucide-react';
import { api, ReportSummary, formatInvokeError } from '../services/tauriApi';
import { ConfirmModal, useConfirmModal } from '../components/ConfirmModal';

const REPORT_TYPES = [
  { key: 'weekly', label: '周报', days: 7 },
  { key: 'monthly', label: '月报', days: 30 },
  { key: 'adhoc', label: '自定义', days: 0 },
];

function isoTimeAgo(days: number): string {
  return new Date(Date.now() - days * 86400 * 1000).toISOString();
}

function isoNow(): string {
  return new Date().toISOString();
}

/**
 * 安全解析日期输入框的值为 ISO 字符串。
 * 空值或非法值返回空串，不抛异常（修复 P0-01：日期输入崩溃）。
 */
function safeParseDateInput(value: string): string {
  if (!value || value.trim() === '') return '';
  // <input type="date"> 返回 "YYYY-MM-DD" 格式，直接使用，不做时区转换
  // B-01 修复：避免 new Date(value).toISOString() 导致跨时区日期偏移一天
  // （如 UTC+8 输入 "2026-07-31" 会变成 "2026-07-30T16:00:00Z"）
  const datePattern = /^\d{4}-\d{2}-\d{2}$/;
  if (!datePattern.test(value)) return '';
  return value;
}

/**
 * 安全截取 ISO 日期字符串前 n 位，null/undefined 返回占位符。
 */
function safeSlice(val: string | null | undefined, n: number, placeholder = '--'): string {
  if (!val) return placeholder;
  try {
    return val.slice(0, n);
  } catch {
    return placeholder;
  }
}

/**
 * 安全格式化日期为本地字符串，无效日期返回占位符。
 */
function safeFormatDate(val: string | null | undefined, placeholder = '--'): string {
  if (!val) return placeholder;
  try {
    const d = new Date(val);
    if (isNaN(d.getTime())) return placeholder;
    return d.toLocaleString();
  } catch {
    return placeholder;
  }
}

export default function Reports() {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [previewContent, setPreviewContent] = useState<string | null>(null);
  const [customStart, setCustomStart] = useState('');
  const [customEnd, setCustomEnd] = useState('');
  // P1修复：补全预览和删除的加载状态
  const [previewing, setPreviewing] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const { modalProps: confirmModalProps, confirm } = useConfirmModal();

  const fetchReports = useCallback(async () => {
    try {
      const list = await api.listReports(100);
      setReports(list);
      setError(null);
    } catch (e) {
      setError(formatInvokeError(e, '加载报告列表'));
    }
  }, []);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const handleGenerate = async (type: string, days: number) => {
    // P1-08 修复：自定义周期校验 start <= end，且范围不超过 90 天
    if (days === 0 && customStart && customEnd) {
      if (customStart > customEnd) {
        setError('起始日期不能晚于结束日期，请重新选择');
        return;
      }
      const startMs = new Date(customStart).getTime();
      const endMs = new Date(customEnd).getTime();
      const rangeDays = (endMs - startMs) / 86400000;
      if (rangeDays > 90) {
        setError('自定义周期不能超过 90 天，请缩小范围');
        return;
      }
    }
    setLoading(true);
    setError(null);
    try {
      const start = days > 0 ? isoTimeAgo(days) : (customStart || isoTimeAgo(7));
      const end = days > 0 ? isoNow() : (customEnd || isoNow());
      await api.generateReport(type, start, end);
      await fetchReports();
    } catch (e: any) {
      setError(formatInvokeError(e, '生成报告'));
    } finally {
      setLoading(false);
    }
  };

  const handlePreview = async (reportId: number) => {
    setPreviewing(true);
    try {
      const result = await api.getReport(reportId);
      setPreviewContent(result.content);
    } catch (e) {
      setError(formatInvokeError(e, '加载报告内容'));
    } finally {
      setPreviewing(false);
    }
  };

  const handleDelete = async (reportId: number) => {
    // P0-03 修复：删除前强制二次确认
    if (!(await confirm('确定要删除这份报告吗？删除后不可恢复。'))) {
      return;
    }
    setDeletingId(reportId);
    try {
      await api.deleteReport(reportId);
      await fetchReports();
      if (previewContent) setPreviewContent(null);
    } catch (e) {
      setError(formatInvokeError(e, '删除报告'));
    } finally {
      setDeletingId(null);
    }
  };

  const typeLabel = (t: string) => REPORT_TYPES.find(r => r.key === t)?.label || t;

  return (
    <div className="page reports-page">
      {error && (
        <div className="alert-banner alert-danger">
          <AlertTriangle size={18} strokeWidth={1.5} className="alert-icon" />
          <span>{error}</span>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>生成安全报告</h3>
        </div>
        <div className="card-body">
          <div className="report-generate-buttons">
            {REPORT_TYPES.map(r => (
              <button
                key={r.key}
                className="btn btn-primary"
                disabled={loading}
                onClick={() => handleGenerate(r.key, r.days)}
              >
                {loading ? '生成中...' : `生成${r.label}`}
              </button>
            ))}
          </div>
          <div className="report-custom-range">
            <label>自定义周期：</label>
            <input
              type="date"
              value={customStart ? safeSlice(customStart, 10) : ''}
              onChange={(e) => setCustomStart(safeParseDateInput(e.target.value))}
            />
            <span> 至 </span>
            <input
              type="date"
              value={customEnd ? safeSlice(customEnd, 10) : ''}
              onChange={(e) => setCustomEnd(safeParseDateInput(e.target.value))}
            />
          </div>
        </div>
      </div>

      {previewContent && (
        <div className="card report-preview-card">
          <div className="card-header">
            <h3>报告预览</h3>
            <button className="btn btn-secondary" onClick={() => setPreviewContent(null)}>关闭</button>
          </div>
          <div className="card-body">
            <iframe
              srcDoc={previewContent}
              className="report-preview-iframe"
              title="报告预览"
              sandbox=""
            />
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>历史报告 ({reports.length})</h3>
        </div>
        <div className="card-body">
          {reports.length === 0 ? (
            <div className="empty-state">暂无历史报告，请先生成一份报告</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>报告类型</th>
                  <th>生成时间</th>
                  <th>周期</th>
                  <th>摘要</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((r) => (
                  <tr key={r.id}>
                    <td><span className="report-type-badge">{typeLabel(r.report_type)}</span></td>
                    <td className="mono">{safeFormatDate(r.generated_at)}</td>
                    <td className="mono">{safeSlice(r.period_start, 10)} ~ {safeSlice(r.period_end, 10)}</td>
                    <td>{r.summary || '--'}</td>
                    <td>
                      <button className="btn btn-sm btn-secondary" onClick={() => handlePreview(r.id)} disabled={previewing}>{previewing ? '加载中...' : '预览'}</button>
                      {' '}
                      <button className="btn btn-sm btn-danger" onClick={() => handleDelete(r.id)} disabled={deletingId === r.id}>{deletingId === r.id ? '删除中...' : '删除'}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
      <ConfirmModal {...confirmModalProps} />
    </div>
  );
}
