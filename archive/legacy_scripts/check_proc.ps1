Get-Process python -ErrorAction SilentlyContinue | Format-Table Id, ProcessName, StartTime -AutoSize | Out-File -FilePath "e:\smallloong\XuanDun\proc_check.txt" -Encoding utf8
