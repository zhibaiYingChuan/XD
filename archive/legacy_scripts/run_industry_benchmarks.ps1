# 道体·玄盾 行业基准测试 - Windows 一键运行脚本
# 用法: .\run_industry_benchmarks.ps1

$ErrorActionPreference = "Stop"

Write-Host "=== 道体·玄盾 行业基准测试 ===" -ForegroundColor Cyan
Write-Host "开始时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# 1. 运行 OWASP LLM Top 10（使用英文预热改善良性接纳率）
Write-Host "`n[1/3] 运行 OWASP LLM Top 10 套件..." -ForegroundColor Yellow
python -m industry_benchmarks.run --suite owasp_llm_top10 --mode balanced --warmup-en --feedback

# 2. 运行 raucle-bench 兼容套件
Write-Host "`n[2/3] 运行 raucle-bench 兼容套件..." -ForegroundColor Yellow
python -m industry_benchmarks.run --suite raucle_bench_compat --mode balanced --warmup-en

# 3. 运行内部扩展套件
Write-Host "`n[3/3] 运行内部扩展套件..." -ForegroundColor Yellow
python -m industry_benchmarks.run --suite internal_extended --mode balanced

# 4. 生成汇总报告
Write-Host "`n[4/5] 生成汇总报告..." -ForegroundColor Yellow
python -m industry_benchmarks.run --summary

# 5. 导出 raucle-bench 提交文件
Write-Host "`n[5/5] 导出 raucle-bench 提交文件..." -ForegroundColor Yellow
python -m industry_benchmarks.run --export-raucle

# 6. 导出 Markdown 报告
Write-Host "`n[6/6] 导出 Markdown 报告..." -ForegroundColor Yellow
python -m industry_benchmarks.run --export-report

Write-Host "`n=== 测试完成 ===" -ForegroundColor Green
Write-Host "结果保存在 industry_benchmarks/results/ 目录"
Write-Host "raucle-bench 提交文件: industry_benchmarks/results/raucle_bench_submission.json"
Write-Host "Markdown 报告: docs/benchmarks.md"
Write-Host "完成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
