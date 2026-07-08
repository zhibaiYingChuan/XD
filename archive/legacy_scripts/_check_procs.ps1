Get-Process | Where-Object { $_.ProcessName -match 'Trae|Cursor|Code|Claude|MarsCode|lingma|codegeex|comate|codebuddy|iflycode' } | Select-Object ProcessName, Id | Format-Table -AutoSize
