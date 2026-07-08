Get-Process | Where-Object { $_.ProcessName -match 'xuandun' } | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Output "Stopped xuandun processes"
Get-Process | Where-Object { $_.ProcessName -match 'xuandun' } | Select-Object ProcessName, Id
