# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

这是一个部署在腾讯云 SCF（云函数）的自动化 Let's Encrypt 证书管理项目。使用**纯 Go ACMEv2 实现**（基于 go-acme/lego），通过 DNS-01 挑战配合 DNSPod API 申请证书，然后上传到腾讯云 SSL 证书服务，可部署到 CDN、CLB、API 网关等资源。**支持同步证书到七牛云 CDN**。

## 核心架构

```
cmd/scf/main.go (SCF 入口)
cmd/cli/main.go (CLI 入口)
    ↓
pkg/handler/certificate.go (CertificateHandler - 核心业务逻辑)
    ↓
pkg/acme/ (ACMEv2 协议实现 - 基于 lego)
pkg/dns/ (DNS-01 挑战处理 - DNSPod 集成)
pkg/cert/ (证书存储、验证、过期检查)
pkg/ssl/ (腾讯云 SSL 证书服务)
pkg/qiniu/ (七牛云证书同步)
pkg/config/ (配置管理)
pkg/domain/ (域名解析)
pkg/notify/ (Webhook 通知)
pkg/response/ (API 响应封装)
```

### 目录结构

```
ssl-manager/
├── cmd/
│   ├── scf/          # SCF 云函数入口
│   └── cli/          # CLI 工具入口
├── pkg/
│   ├── acme/         # ACME 客户端封装 (基于 lego)
│   ├── cert/         # 证书存储、解析、验证
│   ├── config/       # 配置加载和验证
│   ├── dns/          # DNS 挑战处理 (DNSPod)
│   ├── domain/       # 域名解析和处理
│   ├── notify/       # Webhook 通知
│   ├── qiniu/        # 七牛云证书同步客户端
│   ├── response/     # API 响应结构
│   └── ssl/          # 腾讯云 SSL 服务客户端
├── Makefile          # 构建脚本
├── go.mod
└── go.sum
```

## 核心模块说明

### pkg/acme - ACME 客户端

| 文件 | 功能 |
|------|------|
| `types.go` | ACME 用户、证书结果等类型定义 |
| `user.go` | ACME 用户实现 (lego.User 接口) |
| `client.go` | ACME 客户端封装 |

**Client 关键方法：**
- `RequestCertificate(ctx, domains, addCallback, cleanupCallback)` - 申请证书
- `SetDNSProvider(provider)` - 设置 DNS 提供商

### pkg/dns - DNS 挑战处理

| 文件 | 功能 |
|------|------|
| `provider.go` | DNS Provider 接口定义 |
| `tencentcloud.go` | DNSPod Provider 实现 |
| `challenge.go` | DNS-01 挑战处理器 |

**ChallengeHandler 关键方法：**
- `AddValidationRecord(ctx, name, value, ttl)` - 添加 DNS 验证记录
- `CleanupRecord(ctx, record)` - 清理 DNS 记录
- `CleanupRecords(ctx)` - 清理所有记录
- `GetRecordByName(name)` - 根据名称获取记录

**TencentCloudProvider 实现：**
- 使用腾讯云 SDK 操作 DNSPod API
- `Present(domain, token, keyAuth)` - 添加 TXT 记录
- `CleanUp(domain, token, keyAuth)` - 删除 TXT 记录

### pkg/ssl - 腾讯云 SSL 服务

| 文件 | 功能 |
|------|------|
| `client.go` | SSL 服务客户端 |
| `certificate.go` | 证书操作 (上传、查询、删除) |
| `scf.go` | SCF 部署相关 |
| `deployment.go` | 证书部署到云资源 |

**Client 关键方法：**
| 方法 | 功能 |
|---|---|
| `UploadCertificate(ctx, certPEM, keyPEM)` | 上传证书到腾讯云 |
| `GetCertificateList(ctx, limit, offset, searchKey)` | 获取证书列表 |
| `GetCertificateByDomain(ctx, domain)` | 根据域名查询证书 |
| `GetCertificateID(ctx, domain)` | 根据域名获取证书 ID |
| `DeleteCertificate(ctx, certID)` | 删除证书 |

**DeploymentOperations 关键方法：**
| 方法 | 功能 |
|---|---|
| `Deploy(ctx, certID, resourceType, resourceIDs, domain)` | 部署证书到云资源 |
| `DeployToCDN(ctx, certID, domain)` | 部署到 CDN |
| `DeployToCLB(ctx, certID, listenerIDs)` | 部署到负载均衡 |

**支持的资源类型：**
`clb`, `cdn`, `waf`, `live`, `ddos`, `teo`, `apigateway`, `vod`, `tke`, `tcb`, `tse`, `cos`, `scf`

**CertificateOperations 关键方法：**
| 方法 | 功能 |
|---|---|
| `Upload(ctx, certPEM, keyPEM)` | 上传证书 |
| `GetByDomain(ctx, domain)` | 根据域名获取证书 |
| `GetID(ctx, domain)` | 根据域名获取证书 ID |
| `Delete(ctx, certID)` | 删除证书 |
| `CheckStatus(ctx, certID)` | 检查证书状态 |
| `List(ctx, limit, offset, searchKey)` | 列出证书 |

**证书验证函数：**
- `ValidateCertificate(certPEM, keyPEM)` - 验证证书和私钥格式

### pkg/qiniu - 七牛云证书同步

| 文件 | 功能 |
|------|------|
| `types.go` | 七牛 API 类型定义 |
| `client.go` | 七牛客户端（认证、HTTP 请求） |
| `certificate.go` | 证书操作（上传、列表、删除） |

**Client 关键方法：**
| 方法 | 功能 |
|---|---|
| `NewClient(accessKey, secretKey)` | 创建七牛客户端 |
| `IsEnabled()` | 检查客户端是否可用 |
| `UploadCertificate(ctx, name, commonName, privateKey, certChain)` | 上传证书到七牛 |
| `ListCertificates(ctx)` | 获取证书列表 |
| `GetCertificatesByDomain(ctx, domain)` | 根据域名查找证书列表 |
| `Delete(ctx, certID)` | 删除证书 |

**七牛证书同步流程：**
1. 检查七牛客户端是否配置（`QINIU_ACCESS_KEY` 和 `QINIU_SECRET_KEY`）
2. 调用 `GetCertificatesByDomain()` 查找该域名的证书，若结果为空则跳过同步
3. 上传新证书到七牛
4. 如果存在 2 个及以上旧证书，删除最旧的一个

### pkg/domain - 域名解析

| 文件 | 功能 |
|------|------|
| `parser.go` | 域名解析和处理 |

**关键函数：**
- `ParseDomain(domain)` - 解析域名为主域名和子域名
- `IsWildcardDomain(domain)` - 检查是否为通配符域名
- `ExtractBaseDomain(domain)` - 提取基础域名
- `GetDNSRecordName(domain)` - 获取 DNS 记录名称
- `NormalizeDomain(domain)` - 规范化域名
- `GetAcmeChallengeDomain(domain)` - 获取 ACME 挑战域名

### pkg/cert - 证书处理

| 文件 | 功能 |
|------|------|
| `storage.go` | 证书文件存储 |
| `parser.go` | 证书解析 |
| `validator.go` | 证书验证 |
| `expiry.go` | 过期检查 |

**CertificateStorage 关键方法：**
- `SaveCertificate(ctx, domain, certPEM, keyPEM)` - 保存证书和私钥
- `SaveCSR(ctx, domain, csrPEM)` - 保存 CSR
- `LoadCertificate(ctx, domain)` - 加载证书
- `LoadPrivateKey(ctx, domain)` - 加载私钥
- `LoadBoth(ctx, domain)` - 同时加载证书和私钥
- `DomainExists(ctx, domain)` - 检查证书是否存在
- `DeleteDomain(ctx, domain)` - 删除证书
- `ListDomains(ctx)` - 列出所有域名
- `GetCertPath(domain)` - 获取证书文件路径
- `GetKeyPath(domain)` - 获取私钥文件路径

**ExpiryChecker 关键方法：**
- `CheckAllCertificates(ctx, sslClient)` - 检查所有证书过期状态
- `CheckCertificate(ctx, certMap)` - 检查单个证书

### pkg/handler - 业务逻辑处理

**CertificateHandler 核心方法：**

| 方法 | 功能 |
|---|---|
| `IssueCertificate(ctx, domain, extraDomains)` | 申请证书并上传到腾讯云（可选同步到七牛） |
| `IssueCertificateLocal(ctx, domain, extraDomains)` | 本地申请证书（不上传），返回证书路径和 PEM 内容 |
| `RenewCertificate(ctx, domain)` | 续期证书（可选同步到七牛） |
| `ListCertificates(ctx, searchDomain)` | 列出证书 |
| `UploadCertificate(ctx, domain, certDir)` | 上传已有证书 |
| `DeployCertificate(ctx, domain, resourceType, resourceIDs)` | 部署证书 |
| `CheckAndRenew(ctx)` | 检查并自动续期 |
| `syncToQiniu(ctx, domain, certPEM, keyPEM)` | 同步证书到七牛（内部方法） |

## ACME 证书申请流程

1. **CertificateHandler.IssueCertificate()** 协调整个流程
2. 通过 **acme.Client** 创建 ACME 客户端 (基于 lego)
3. 调用 **RequestCertificate()** 发起证书申请：
   - 通过 DNS Provider 添加 TXT 记录 (`Present()`)
   - 等待 DNS 传播（可配置，默认 60 秒）
   - lego 自动完成挑战验证
   - 清理 DNS 记录 (`CleanUp()`)
4. 保存证书到 `{ACME_HOME_DIR}/certs/{domain}/` 目录
5. 调用 **ssl.Client.UploadCertificate()** 上传到腾讯云

## API 接口 (SCF 入口)

`cmd/scf/main.go` 的 `Handler` 支持三种触发方式：

- **定时触发器**：`check` - 自动续期即将过期证书
- **API 网关**：REST 接口
  - `POST /certificate/issue` - 申请新证书并上传到腾讯云
  - `POST /certificate/renew` - 续期证书
  - `POST /certificate/deploy` - 部署证书到云资源
  - `GET /certificate/list` - 列出证书
- **直接调用**：`{"action": "issue|renew|deploy|list|check|upload", ...}`

### 可用操作（Actions）

| Action | 功能 | 参数 |
|---|---|
| `issue` | 申请新证书并上传到腾讯云 | `domain`, `staging` |
| `renew` | 续期证书 | `domain` |
| `deploy` | 部署证书到云资源 | `domain`, `resourceType`, `resourceIds` |
| `list` | 列出证书 | `domain`（可选） |
| `check` | 检查并自动续期即将过期证书 | 无 |
| `upload` | 上传已有证书到腾讯云 | `domain`, `certDir`（可选） |

### 证书存储路径

证书文件存储在 `{ACME_HOME_DIR}/certs/{domain}/` 目录：

```
{ACME_HOME_DIR}/
├── accounts/           # ACME 账户密钥
└── certs/
    └── {domain}/       # 按域名分类
        ├── fullchain.pem   # 完整证书链
        ├── privkey.pem     # 私钥
        └── cert.csr        # 证书签名请求
```

## CLI 命令

```bash
# 构建
make cli               # 构建 CLI 工具
make scf               # 构建 SCF 二进制
make scf-package       # 打包 SCF 部署包

# 证书管理
./ssl-manager issue cdn.example.com           # 申请证书并上传到腾讯云
./ssl-manager issue-local cdn.example.com      # 本地申请证书（不上传）
./ssl-manager issue-local cdn.example.com --email admin@example.com  # 指定邮箱
./ssl-manager renew cdn.example.com           # 续期证书(无视已有证书的可用时长)
./ssl-manager list                            # 列出证书
./ssl-manager list cdn.example.com            # 查询指定域名
./ssl-manager check                           # 检查并续期
./ssl-manager upload cdn.example.com          # 上传已有证书
./ssl-manager upload cdn.example.com --cert-dir /path/to/certs  # 指定证书目录
```

## 配置说明

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `TENCENT_SECRET_ID` | 腾讯云 Secret ID | (必需) |
| `TENCENT_SECRET_KEY` | 腾讯云 Secret Key | (必需) |
| `TENCENT_REGION` | 地域 | `ap-guangzhou` |
| `ACME_ACCOUNT_EMAIL` | ACME 账户邮箱 | `admin@example.com` |
| `ACME_HOME_DIR` | 证书存储根目录 | `/tmp/acme` |
| `ACME_DNS_PROPAGATION` | DNS 传播等待时间(秒) | `60` |
| `ACME_STAGING` | 使用 Let's Encrypt 测试环境 | `false` |
| `CERT_EXPIRY_WARNING_DAYS` | 证书过期预警天数 | `30` |
| `NOTIFY_ENABLED` | 启用 Webhook 通知 | `false` |
| `NOTIFY_WEBHOOK` | Webhook URL | - |
| `QINIU_ACCESS_KEY` | 七牛云 AccessKey（可选） | - |
| `QINIU_SECRET_KEY` | 七牛云 SecretKey（可选） | - |
| `SSL_UPDATE_CONFIG_{DOMAIN}` | 域名特定的证书更新资源配置（JSON 数组） | - |

### 证书更新资源配置

`SSL_UPDATE_CONFIG_*` 环境变量用于配置证书续期时需要更新的云资源类型和地域。

#### 命名规则

- 域名中的 `.` 替换为 `_`，转换为全大写
- 例如：`cdn.example.com` → `SSL_UPDATE_CONFIG_CDN_EXAMPLE_COM`

#### JSON 格式

```json
[
  {"type": "cdn"},
  {"type": "clb", "regions": ["ap-guangzhou", "ap-shanghai"]},
  {"type": "waf", "regions": ["ap-guangzhou"]}
]
```


#### 支持的资源类型

| 类型 | 需要地域 | 说明 |
|------|---------|------|
| `cdn` | 否 | 内容分发网络 |
| `clb` | 是 | 负载均衡 |
| `waf` | 是 | Web 应用防火墙 |
| `live` | 否 | 云直播 |
| `ddos` | 否 | DDoS 防护 |
| `teo` | 否 | 边缘安全加速 |
| `apigateway` | 是 | API 网关 |
| `vod` | 否 | 云点播 |
| `tke` | 是 | 容器服务 |
| `tcb` | 是 | 云开发 |
| `tse` | 是 | 微服务引擎 |
| `cos` | 是 | 对象存储 |

#### 配置示例

```bash
# 域名特定配置（支持多级域名）
SSL_UPDATE_CONFIG_WWW_EXAMPLE_COM=[{"type":"cdn"}]

SSL_UPDATE_CONFIG_API_SUB_EXAMPLE_COM=[{"type":"clb","regions":["ap-guangzhou","ap-shanghai"]},{"type":"cdn"}]
```

### SCF 环境约束

- **超时限制**：SCF 最大 300 秒，典型证书申请需 40-90 秒
- **工作目录**：证书存储在 `{ACME_HOME_DIR}/certs/{domain}/`，默认 `/tmp/acme/certs/{domain}/`
- **冷启动**：首次运行会生成账户密钥，缓存在 `/tmp/acme/`

### 证书存储结构

| 环境 | 证书路径 |
|------|----------|
| **SCF 云函数** | `/tmp/acme/certs/{domain}/fullchain.pem` |
| **SCF 云函数** | `/tmp/acme/certs/{domain}/privkey.pem` |
| **本地 CLI** | 由 `ACME_HOME_DIR` 环境变量指定 |

### Let's Encrypt 限制

- 生产环境：每周每域名最多 5 个证书
- 测试环境（staging）：无限制（设置 `ACME_STAGING=true`）
- 建议设置 `ACME_ACCOUNT_EMAIL` 环境变量以接收证书过期提醒

### 腾讯云 SDK 使用

使用腾讯云 Go SDK 时参考官方 API 文档：
- SSL 证书服务：https://cloud.tencent.com/document/product/400/41681
- DNSPod API：https://cloud.tencent.com/document/product/1427/56194

**Go SDK 使用要点：**
- 使用 `tencentcloud/common/profile` 构建请求
- 使用 `tencentcloud/common/region` 选择地域
- 返回值通过类型断言获取具体字段

## 依赖

- `github.com/go-acme/lego/v4` - ACMEv2 协议实现
- `github.com/tencentcloud/tencentcloud-sdk-go` - 腾讯云 Go SDK
- `github.com/qiniu/go-sdk/v7` - 七牛云 Go SDK（用于证书同步）

## 构建目标

| 目标 | 说明 |
|------|------|
| `make deps` | 下载依赖 |
| `make cli` | 构建 CLI 二进制 |
| `make scf` | 构建 SCF 二进制 (Linux) |
| `make scf-package` | 打包 SCF 部署包 |
| `make test` | 运行测试 |
| `make clean` | 清理构建文件 |
