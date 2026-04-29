# 从 .env 文件加载环境变量
$envFile = Join-Path $PSScriptRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#')) {
            $parts = $line.Split('=', 2)
            if ($parts.Length -eq 2) {
                $key = $parts[0].Trim()
                $value = $parts[1].Trim()
                Write-Host "Loaded: $key" -ForegroundColor Green
                [Environment]::SetEnvironmentVariable($key, $value, "Process")
            }
        }
    }
}

# 运行 cli.exe 并传递所有参数
& (Join-Path $PSScriptRoot "cli.exe") @args
