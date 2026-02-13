# SSL Manager Go

腾讯云 SCF 部署的 Let's Encrypt 证书管理 - Go 实现

## 特性

- 纯 Go 实现 ACMEv2 协议（使用 go-acme/lego）
- DNS-01 挑战验证（通过 DNSPod API）
- 自动上传证书到腾讯云 SSL 服务
- 支持部署到 CDN、CLB、API 网关等资源
- 自动续期即将过期的证书

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| TENCENT_SECRET_ID | 腾讯云 Secret ID | (必需) |
| TENCENT_SECRET_KEY | 腾讯云 Secret Key | (必需) |
| TENCENT_REGION | 地域 | ap-guangzhou |
| ACME_ACCOUNT_EMAIL | ACME 账户邮箱 | admin@example.com |
| ACME_HOME_DIR | 工作目录 | /tmp/acme |
| ACME_DNS_PROPAGATION | DNS 传播等待时间(秒) | 60 |
| ACME_STAGING | 使用 Let's Encrypt 测试环境 | false |
| CERT_EXPIRY_WARNING_DAYS | 证书过期预警天数 | 30 |
| NOTIFY_ENABLED | 启用 Webhook 通知 | false |
| NOTIFY_WEBHOOK | Webhook URL | - |

## 构建和部署

```bash
# 安装依赖
make deps

# 构建 SCF 二进制
make scf

# 构建 CLI 工具
make cli

# 打包 SCF 部署包
make scf-package

# 运行测试
make test
```

## CLI 命令

```bash
# 申请证书并上传到腾讯云
./build/cli issue cdn.example.com

# 本地申请证书
./build/cli issue-local cdn.example.com

# 续期证书
./build/cli renew cdn.example.com

# 列出证书
./build/cli list

# 检查并续期
./build/cli check

# 上传已有证书
./build/cli upload cdn.example.com
```