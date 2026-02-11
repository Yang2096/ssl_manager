# SSL Certificate Manager - Windows Deployment Script
# 用于将代码打包并部署到腾讯云 SCF

param(
    [Parameter(Position=0)]
    [ValidateSet('package', 'serverless', 'clean')]
    [string]$Method = 'package'
)

# 颜色函数
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# 检查环境变量
function Test-EnvironmentVariables {
    Write-Info "Checking environment variables..."

    $requiredVars = @(
        'TENCENT_SECRET_ID',
        'TENCENT_SECRET_KEY'
    )

    $missing = 0
    foreach ($var in $requiredVars) {
        $value = [Environment]::GetEnvironmentVariable($var)
        if ([string]::IsNullOrEmpty($value)) {
            Write-Error "$var is not set"
            $missing++
        }
    }

    if ($missing -gt 0) {
        Write-Error "Missing $missing required environment variables"
        exit 1
    }

    Write-Info "All required environment variables are set"
}

# 检查 acme.sh 组件
function Test-AcmeComponents {
    Write-Info "Checking acme.sh components..."

    if (-not (Test-Path 'acme_lib\acme.sh')) {
        Write-Error "acme_lib\acme.sh not found"
        exit 1
    }

    if (-not (Test-Path 'acme_lib\dnsapi')) {
        Write-Error "acme_lib\dnsapi directory not found"
        exit 1
    }

    if (-not (Test-Path 'acme_lib\dnsapi\dns_dp.sh')) {
        Write-Error "acme_lib\dnsapi\dns_dp.sh not found"
        exit 1
    }

    Write-Info "acme.sh components verified"
}

# 安装依赖
function Install-Dependencies {
    Write-Info "Installing Python dependencies..."

    if (-not (Test-Path 'package')) {
        New-Item -ItemType Directory -Path 'package' | Out-Null
    }

    pip install -r requirements.txt -t package/

    Write-Info "Dependencies installed"
}

# 复制代码文件
function Copy-CodeFiles {
    Write-Info "Copying code files..."

    # 复制所有 Python 文件到 package 目录
    Get-ChildItem -Filter *.py | ForEach-Object {
        Copy-Item $_.FullName -Destination 'package\' -Force
    }

    # 复制 acme_lib 目录
    Copy-Item -Path 'acme_lib' -Destination 'package\acme_lib' -Recurse -Force

    Write-Info "Code files copied"
}

# 打包
function New-Package {
    Write-Info "Creating deployment package..."

    # 删除旧的压缩包
    if (Test-Path 'deployment_package.zip') {
        Remove-Item 'deployment_package.zip'
    }

    Compress-Archive -Path package\* -DestinationPath deployment_package.zip -Force

    Write-Info "Deployment package created: deployment_package.zip"
}

# 清理
function Invoke-Cleanup {
    Write-Info "Cleaning up..."

    if (Test-Path 'package') {
        Remove-Item -Recurse -Force 'package'
    }

    Write-Info "Cleanup completed"
}

# 主流程
function Main {
    Write-Info "SSL Certificate Manager - Deployment Script (Windows)"
    Write-Host ""

    switch ($Method) {
        'package' {
            Test-EnvironmentVariables
            Test-AcmeComponents
            Install-Dependencies
            Copy-CodeFiles
            New-Package
            Invoke-Cleanup
            Write-Info "Deployment package ready: deployment_package.zip"
            Write-Info "Upload it manually via Tencent Cloud Console"
        }
        'serverless' {
            Test-EnvironmentVariables
            Test-AcmeComponents
            if (-not (Get-Command serverless -ErrorAction SilentlyContinue)) {
                Write-Error "Serverless Framework is not installed"
                Write-Info "Install it with: npm install -g serverless"
                exit 1
            }
            serverless deploy
        }
        'clean' {
            Invoke-Cleanup
            if (Test-Path 'deployment_package.zip') {
                Remove-Item 'deployment_package.zip'
            }
            Write-Info "Cleaned up"
        }
    }
}

# 运行主流程
Main
