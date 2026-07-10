# SPDX-License-Identifier: DaoTi-Research-1.0
# Copyright (c) 2026 独立研究者，知白
# 本文件受道体研究许可证 v1.0 约束，禁止逆向工程和再分发
# 详见 LICENSE 文件

"""安全报告生成引擎 — 支持周报/月报/自定义周期报告。

生成流程：
  1. 从 logs 表聚合周期内统计数据
  2. 使用 matplotlib 生成图表 PNG（base64 嵌入）
  3. 使用内置模板渲染 HTML / Markdown 格式报告
  4. 归档到 SQLite reports 表

依赖：matplotlib (Agg backend), 无需 Jinja2（内置字符串模板）
"""

import base64
import io
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Tuple

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ATTACK_CATEGORY_NAMES = {
    'direct_prompt_injection': '直接提示注入',
    'indirect_prompt_injection': '间接提示注入',
    'jailbreak': '越狱攻击',
    'encoding_obfuscation': '编码混淆',
    'agent_attack': 'Agent攻击',
    'data_leakage': '数据泄露',
    'other': '其他',
}


class ReportGenerator:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def generate(self, report_type: str, period_start: str, period_end: str) -> Dict[str, Any]:
        stats = self._aggregate_stats(period_start, period_end)
        charts = self._render_charts(stats, period_start, period_end)
        summary = self._build_summary(stats, report_type, period_start, period_end)
        html = self._render_html(stats, charts, summary, report_type, period_start, period_end)
        markdown = self._render_markdown(stats, charts, summary, report_type, period_start, period_end)
        return {
            'report_type': report_type,
            'period_start': period_start,
            'period_end': period_end,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'summary': summary,
            'html': html,
            'markdown': markdown,
            'stats': stats,
        }

    def _aggregate_stats(self, start: str, end: str) -> Dict[str, Any]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT COUNT(*) as total, SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) as blocked FROM logs WHERE timestamp >= ? AND timestamp < ?",
                (start, end)
            ).fetchone()
            total = row['total'] or 0
            blocked = row['blocked'] or 0

            cat_rows = conn.execute(
                "SELECT COALESCE(attack_category, 'unknown') as cat, COUNT(*) as cnt FROM logs WHERE timestamp >= ? AND timestamp < ? AND allowed = 0 GROUP BY cat ORDER BY cnt DESC",
                (start, end)
            ).fetchall()
            categories = [{'category': r['cat'], 'name': ATTACK_CATEGORY_NAMES.get(r['cat'], r['cat']), 'count': r['cnt']} for r in cat_rows]

            daily_rows = conn.execute(
                "SELECT DATE(timestamp) as day, COUNT(*) as total, SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) as blocked FROM logs WHERE timestamp >= ? AND timestamp < ? GROUP BY day ORDER BY day",
                (start, end)
            ).fetchall()
            daily = [{'day': r['day'], 'total': r['total'], 'blocked': r['blocked']} for r in daily_rows]

            stage_rows = conn.execute(
                "SELECT COALESCE(reject_stage, 'unknown') as stage, COUNT(*) as cnt FROM logs WHERE timestamp >= ? AND timestamp < ? AND allowed = 0 GROUP BY stage ORDER BY cnt DESC",
                (start, end)
            ).fetchall()
            stages = [{'stage': r['stage'], 'count': r['cnt']} for r in stage_rows]

            sample_rows = conn.execute(
                "SELECT text_preview, attack_category, reject_stage FROM logs WHERE timestamp >= ? AND timestamp < ? AND allowed = 0 ORDER BY id DESC LIMIT 10",
                (start, end)
            ).fetchall()
            samples = [{'text': r['text_preview'], 'category': r['attack_category'], 'stage': r['reject_stage']} for r in sample_rows]

            return {
                'total': total,
                'blocked': blocked,
                'allowed': total - blocked,
                'block_rate': (blocked / total * 100) if total > 0 else 0.0,
                'categories': categories,
                'daily': daily,
                'stages': stages,
                'samples': samples,
            }
        finally:
            conn.close()

    def _render_charts(self, stats: Dict, start: str, end: str) -> Dict[str, str]:
        charts = {}
        plt.style.use('dark_background')

        if stats['daily']:
            days = [d['day'][-5:] for d in stats['daily']]
            totals = [d['total'] for d in stats['daily']]
            blockeds = [d['blocked'] for d in stats['daily']]
            fig, ax = plt.subplots(figsize=(8, 3))
            ax.bar(days, totals, label='请求', alpha=0.7, color='#4ecdc4')
            ax.bar(days, blockeds, label='拦截', alpha=0.9, color='#ff6b6b')
            ax.set_title('每日拦截趋势', fontsize=12)
            ax.legend(fontsize=9)
            ax.tick_params(axis='x', labelsize=8, rotation=30)
            ax.tick_params(axis='y', labelsize=9)
            charts['trend'] = self._fig_to_base64(fig)
            plt.close(fig)
        else:
            charts['trend'] = ''

        if stats['categories']:
            labels = [c['name'] for c in stats['categories']]
            sizes = [c['count'] for c in stats['categories']]
            colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#f9ca24', '#6c5ce7', '#a29bfe', '#fd79a8']
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors[:len(labels)], textprops={'fontsize': 9})
            ax.set_title('攻击类型分布', fontsize=12)
            charts['distribution'] = self._fig_to_base64(fig)
            plt.close(fig)
        else:
            charts['distribution'] = ''

        return charts

    def _fig_to_base64(self, fig) -> str:
        buf = io.BytesIO()
        fig.savefig(buf, format='png', dpi=100, bbox_inches='tight')
        buf.seek(0)
        return base64.b64encode(buf.read()).decode('utf-8')

    def _build_summary(self, stats: Dict, report_type: str, start: str, end: str) -> Dict[str, Any]:
        top_cat = stats['categories'][0] if stats['categories'] else None
        return {
            'report_type': report_type,
            'period_start': start,
            'period_end': end,
            'total_requests': stats['total'],
            'total_blocked': stats['blocked'],
            'block_rate': round(stats['block_rate'], 2),
            'top_attack_category': top_cat['name'] if top_cat else '无',
            'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        }

    def _render_html(self, stats: Dict, charts: Dict, summary: Dict, report_type: str, start: str, end: str) -> str:
        type_label = {'weekly': '周报', 'monthly': '月报', 'adhoc': '自定义报告'}.get(report_type, report_type)
        cat_rows = ''.join([
            f"<tr><td>{c['name']}</td><td>{c['count']}</td><td>{(c['count']/stats['blocked']*100) if stats['blocked']>0 else 0:.1f}%</td></tr>"
            for c in stats['categories'][:10]
        ]) or '<tr><td colspan="3">无攻击记录</td></tr>'
        sample_rows = ''.join([
            f"<tr><td>{s['text'][:50]}</td><td>{ATTACK_CATEGORY_NAMES.get(s['category'], s['category'] or '未知')}</td><td>{s['stage'] or '--'}</td></tr>"
            for s in stats['samples']
        ]) or '<tr><td colspan="3">无拦截样本</td></tr>'
        trend_img = f'<img src="data:image/png;base64,{charts["trend"]}" style="max-width:100%"/>' if charts.get('trend') else '<p>无趋势数据</p>'
        dist_img = f'<img src="data:image/png;base64,{charts["distribution"]}" style="max-width:100%"/>' if charts.get('distribution') else '<p>无分布数据</p>'

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>道体·玄盾 安全报告 - {type_label}</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; color: #333; }}
h1 {{ color: #4ecdc4; border-bottom: 2px solid #4ecdc4; padding-bottom: 8px; }}
h2 {{ color: #45b7d1; margin-top: 24px; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; font-size: 13px; }}
th {{ background: #f5f5f5; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }}
.summary-item {{ background: #f9f9f9; padding: 12px; border-radius: 8px; text-align: center; }}
.summary-value {{ font-size: 24px; font-weight: 700; color: #4ecdc4; }}
.summary-label {{ font-size: 12px; color: #999; }}
.chart-container {{ margin: 16px 0; }}
.footer {{ margin-top: 32px; padding-top: 12px; border-top: 1px solid #ddd; font-size: 12px; color: #999; }}
</style></head>
<body>
<h1>道体·玄盾 安全{type_label}</h1>
<p>报告周期：{start[:10]} 至 {end[:10]} | 生成时间：{summary['generated_at']}</p>

<h2>1. 概要摘要</h2>
<div class="summary-grid">
<div class="summary-item"><div class="summary-value">{stats['total']}</div><div class="summary-label">总请求数</div></div>
<div class="summary-item"><div class="summary-value" style="color:#ff6b6b">{stats['blocked']}</div><div class="summary-label">拦截次数</div></div>
<div class="summary-item"><div class="summary-value">{summary['block_rate']}%</div><div class="summary-label">拦截率</div></div>
<div class="summary-item"><div class="summary-value">{stats['allowed']}</div><div class="summary-label">放行次数</div></div>
</div>

<h2>2. 拦截趋势</h2>
<div class="chart-container">{trend_img}</div>

<h2>3. 攻击类型分布</h2>
<div class="chart-container">{dist_img}</div>
<table><thead><tr><th>攻击类型</th><th>拦截量</th><th>占比</th></tr></thead><tbody>{cat_rows}</tbody></table>

<h2>4. 代表性拦截样本</h2>
<table><thead><tr><th>文本摘要</th><th>攻击分类</th><th>拦截阶段</th></tr></thead><tbody>{sample_rows}</tbody></table>

<div class="footer">
<p>本报告由道体·玄盾自动生成 | SPDX-License-Identifier: DaoTi-Research-1.0</p>
<p>数据来源：SQLite logs 表 | 报告类型：{type_label}</p>
</div>
</body></html>"""

    def _render_markdown(self, stats: Dict, charts: Dict, summary: Dict, report_type: str, start: str, end: str) -> str:
        type_label = {'weekly': '周报', 'monthly': '月报', 'adhoc': '自定义报告'}.get(report_type, report_type)
        lines = [
            f"# 道体·玄盾 安全{type_label}",
            f"",
            f"**报告周期**：{start[:10]} 至 {end[:10]}  ",
            f"**生成时间**：{summary['generated_at']}",
            f"",
            f"## 1. 概要摘要",
            f"",
            f"| 指标 | 数值 |",
            f"|------|------|",
            f"| 总请求数 | {stats['total']} |",
            f"| 拦截次数 | {stats['blocked']} |",
            f"| 拦截率 | {summary['block_rate']}% |",
            f"| 放行次数 | {stats['allowed']} |",
            f"| 主要攻击类型 | {summary['top_attack_category']} |",
            f"",
            f"## 2. 攻击类型分布",
            f"",
            f"| 攻击类型 | 拦截量 | 占比 |",
            f"|----------|--------|------|",
        ]
        for c in stats['categories'][:10]:
            pct = (c['count'] / stats['blocked'] * 100) if stats['blocked'] > 0 else 0
            lines.append(f"| {c['name']} | {c['count']} | {pct:.1f}% |")
        if not stats['categories']:
            lines.append("| 无攻击记录 | - | - |")

        lines.extend([
            f"",
            f"## 3. 代表性拦截样本",
            f"",
            f"| 文本摘要 | 攻击分类 | 拦截阶段 |",
            f"|----------|----------|----------|",
        ])
        for s in stats['samples']:
            lines.append(f"| {s['text'][:50]} | {ATTACK_CATEGORY_NAMES.get(s['category'], s['category'] or '未知')} | {s['stage'] or '--'} |")
        if not stats['samples']:
            lines.append("| 无拦截样本 | - | - |")

        lines.extend([
            f"",
            f"---",
            f"",
            f"*本报告由道体·玄盾自动生成 | SPDX-License-Identifier: DaoTi-Research-1.0*",
        ])
        return '\n'.join(lines)
