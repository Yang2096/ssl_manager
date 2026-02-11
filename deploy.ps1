# SSL Certificate Manager - Windows Deployment Script
# Simplified: Copy files and package only

param(
    [Parameter(Position=0)]
    [ValidateSet("package", "clean")]
    [string]$Method = "package"
)

# Copy code files
function Copy-CodeFiles {
    Write-Host "[INFO] Copying code files..." -ForegroundColor Green

    if (-not (Test-Path "package")) {
        New-Item -ItemType Directory -Path "package" | Out-Null
    }

    # Copy all Python files
    Get-ChildItem -Filter "*.py" | ForEach-Object {
        Copy-Item $_.FullName -Destination "package\" -Force
    }

    # Copy requirements.txt
    if (Test-Path "requirements.txt") {
        Copy-Item "requirements.txt" -Destination "package\" -Force
    }

    Write-Host "[INFO] Code files copied" -ForegroundColor Green
}

# Create package
function New-Package {
    Write-Host "[INFO] Creating deployment package..." -ForegroundColor Green

    if (Test-Path "deployment_package.zip") {
        Remove-Item "deployment_package.zip"
    }

    Compress-Archive -Path "package\*" -DestinationPath "deployment_package.zip" -Force

    $size = [math]::Round((Get-Item "deployment_package.zip").Length / 1MB, 2)
    Write-Host "[INFO] Deployment package created: deployment_package.zip ($size MB)" -ForegroundColor Green
}

# Cleanup
function Invoke-Cleanup {
    Write-Host "[INFO] Cleaning up..." -ForegroundColor Green

    if (Test-Path "package") {
        Remove-Item -Recurse -Force "package"
    }

    Write-Host "[INFO] Cleanup completed" -ForegroundColor Green
}

# Main flow
switch ($Method) {
    "package" {
        Write-Host "=== SSL Certificate Manager - Package ===" -ForegroundColor Cyan
        Copy-CodeFiles
        New-Package
        Invoke-Cleanup
        Write-Host "[INFO] Done! Upload deployment_package.zip to Tencent Cloud SCF" -ForegroundColor Green
    }
    "clean" {
        Invoke-Cleanup
        if (Test-Path "deployment_package.zip") {
            Remove-Item "deployment_package.zip"
        }
        Write-Host "[INFO] Cleaned up" -ForegroundColor Green
    }
}
