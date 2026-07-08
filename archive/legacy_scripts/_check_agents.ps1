$userProfile = $env:USERPROFILE
$dirs = @('.vscode\extensions', '.trae-cn\extensions', '.cursor\extensions', '.trae\extensions')
foreach ($d in $dirs) {
    $p = Join-Path $userProfile $d
    Write-Host "=== $p ==="
    if (Test-Path $p) {
        Get-ChildItem $p -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Where-Object { $_ -match 'lingma|codegeex|comate|codebuddy|iflycode|tongyi|alibaba|baidu|tencent' }
    } else {
        Write-Host '(not exist)'
    }
}
