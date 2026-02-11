#!/bin/bash
#
# SSL Certificate Manager - 部署脚本
# 用于将代码打包并部署到腾讯云 SCF
#

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 函数：打印信息
info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查环境变量
check_env() {
    info "Checking environment variables..."

    required_vars=(
        "TENCENT_SECRET_ID"
        "TENCENT_SECRET_KEY"
    )

    missing=0
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            error "$var is not set"
            missing=$((missing + 1))
        fi
    done

    if [ $missing -gt 0 ]; then
        error "Missing $missing required environment variables"
        exit 1
    fi

    info "All required environment variables are set"
}

# 安装依赖
install_deps() {
    info "Installing Python dependencies..."

    if [ ! -d "package" ]; then
        mkdir package
    fi

    pip install -r requirements.txt -t package/

    info "Dependencies installed"
}

# 复制代码文件
copy_files() {
    info "Copying code files..."

    # 复制所有 Python 文件到 package 目录
    cp *.py package/

    info "Code files copied"
}

# 打包
package() {
    info "Creating deployment package..."

    cd package
    zip -r ../deployment_package.zip .
    cd ..

    info "Deployment package created: deployment_package.zip"
}

# 清理
cleanup() {
    info "Cleaning up..."

    rm -rf package

    info "Cleanup completed"
}

# 使用 serverless 部署
deploy_serverless() {
    info "Deploying with Serverless Framework..."

    if ! command -v serverless &> /dev/null; then
        error "Serverless Framework is not installed"
        info "Install it with: npm install -g serverless"
        exit 1
    fi

    serverless deploy

    info "Deployment completed"
}

# 使用腾讯云 CLI 部署
deploy_tencent_cli() {
    info "Deploying with Tencent Cloud CLI..."

    if ! command -v scf &> /dev/null; then
        error "Tencent Cloud CLI is not installed"
        info "Install it from: https://cloud.tencent.com/document/product/436/68808"
        exit 1
    fi

    scf deploy --deployment_package deployment_package.zip

    info "Deployment completed"
}

# 主流程
main() {
    info "SSL Certificate Manager - Deployment Script"
    echo ""

    # 检查参数
    DEPLOY_METHOD="${1:-package}"

    case $DEPLOY_METHOD in
        package)
            check_env
            install_deps
            copy_files
            package
            cleanup
            info "Deployment package ready: deployment_package.zip"
            info "Upload it manually via Tencent Cloud Console"
            ;;
        serverless)
            check_env
            deploy_serverless
            ;;
        cli)
            check_env
            install_deps
            copy_files
            package
            deploy_tencent_cli
            cleanup
            ;;
        clean)
            cleanup
            rm -f deployment_package.zip
            info "Cleaned up"
            ;;
        *)
            error "Unknown deployment method: $DEPLOY_METHOD"
            echo ""
            echo "Usage: $0 [package|serverless|cli|clean]"
            echo ""
            echo "  package     - Create deployment package only (default)"
            echo "  serverless  - Deploy using Serverless Framework"
            echo "  cli         - Deploy using Tencent Cloud CLI"
            echo "  clean       - Clean up build artifacts"
            exit 1
            ;;
    esac
}

# 运行主流程
main "$@"
