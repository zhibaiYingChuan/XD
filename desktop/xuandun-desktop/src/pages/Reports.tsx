import { useState, useEffect, useCallback } from 'react';
import { api, ReportSummary } from '../services/tauriApi';

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

export default function Reports() {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [previewContent, setPreviewContent] = useState<string | null>(null);
  const [customStart, setCustomStart] = useState('');
  const [customEnd, setCustomEnd] = useState('');

  const fetchReports = useCallback(async () => {
    try {
      const list = await api.listReports(100);
      setReports(list);
      setError(null);
    } catch (e) {
      setError('加载报告列表失败');
    }
  }, []);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const handleGenerate = async (type: string, days: number) => {
    setLoading(true);
    setError(null);
    try {
      const start = days > 0 ? isoTimeAgo(days) : (customStart || isoTimeAgo(7));
      const end = days > 0 ? isoNow() : (customEnd || isoNow());
      await api.generateReport(type, start, end);
      await fetchReports();
    } catch (e: any) {
      setError(`生成报告失败: ${e?.toString() || '未知错误'}`);
    } finally {
      setLoading(false);
    }
  };

  const handlePreview = async (reportId: number) => {
    try {
      const result = await api.getReport(reportId);
      setPreviewContent(result.content);
    } catch (e) {
      setError('加载报告内容失败');
    }
  };

  const handleDelete = async (reportId: number) => {
    try {
      await api.deleteReport(reportId);
      await fetchReports();
      if (previewContent) setPreviewContent(null);
    } catch (e) {
      setError('删除报告失败');
    }
  };

  const typeLabel = (t: string) => REPORT_TYPES.find(r => r.key === t)?.label || t;

  return (
    <div className="page reports-page">
      {error && (
        <div className="alert-banner alert-danger">
          <span className="alert-icon">⚠️</span>
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
              value={customStart ? customStart.slice(0, 10) : ''}
              onChange={(e) => setCustomStart(new Date(e.target.value).toISOString())}
            />
            <span> 至 </span>
            <input
              type="date"
              value={customEnd ? customEnd.slice(0, 10) : ''}
              onChange={(e) => setCustomEnd(new Date(e.target.value).toISOString())}
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
                    <td className="mono">{new Date(r.generated_at).toLocaleString()}</td>
                    <td className="mono">{r.period_start.slice(0, 10)} ~ {r.period_end.slice(0, 10)}</td>
                    <td>{r.summary || '--'}</td>
                    <td>
                      <button className="btn btn-sm btn-secondary" onClick={() => handlePreview(r.id)}>预览</button>
                      {' '}
                      <button className="btn btn-sm btn-danger" onClick={() => handleDelete(r.id)}>删除</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
