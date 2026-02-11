# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

这是一个部署在腾讯云 SCF（云函数）的自动化 Let's Encrypt 证书管理项目。使用**纯 Python ACMEv2 实现**（无 Shell 脚本依赖），通过 DNS-01 挑战配合 DNSPod API 申请证书，然后上传到腾讯云 SSL 证书服务，可部署到 CDN、CLB、API 网关等资源。

## 核心架构

```
index.py (SCF 入口)
    ↓
acme_handler.py (AcmeCertificateHandler - 对外 API)
    ↓
acme_client.py (PureACMEClient - ACMEv2 协议实现)
dns_challenge.py (DNSChallengeHandler - DNSPod 集成)
cert_checker.py (CertificateExpiryChecker - 自动续期逻辑)

支撑模块:
- dns_handler.py → DNSPodV3Handler (DNS API，2021-03-23 版本)
- tencent_ssl.py → TencentSSLHandler (SSL 证书 API)
- config.py → Config, AcmeConfig
- utils.py → DomainParser, CertificateUtils, NotificationHandler
```

### ACME 证书申请流程（纯 Python）

1. **PureACMEClient.request_certificate()** 协调整个流程
2. 通过 `ACMEOrder` 创建 ACME 订单
3. 通过 `DNS01Challenge.get_dns_challenges()` 获取 DNS 挑战
4. 对每个挑战：
   - 调用 `dns_record_callback(record_name, record_value)` → 通过 DNSPodV3Handler 添加 TXT 记录
   - 等待 DNS 传播（可配置，默认 60 秒）
   - 通过 `DNS01Challenge.answer_challenge()` 回答挑战
   - 通过 `DNS01Challenge.poll_authorization()` 轮询授权状态
   - 调用 `dns_cleanup_callback()` → 删除 TXT 记录
5. 通过 `CertificateManager` 生成私钥和 CSR
6. 完成订单并下载证书
7. 保存到 `/tmp/acme/{domain}/` 目录为 `fullchain.pem` 和 `privkey.pem`

### DNSPodV3Handler 详情

`dns_handler.py` 提供 DNSPod API V3 客户端：

| 类 | API 版本 | 实现方式 |
|---|---|---|
| `DNSPodV3Handler` | 2021-03-23 | 腾讯云官方 SDK (tencentcloud-sdk-python) |

**DNSPodV3Handler 关键方法：**
- `add_txt_record(domain, sub_domain, value)` - 添加 TXT 记录，返回记录 ID
- `delete_dns_record(domain, record_id)` - 删除指定 ID 的记录
- `get_dns_records(domain, subdomain)` - 查询记录列表

### TencentSSLHandler 详情

`tencent_ssl.py` 提供腾讯云 SSL 证书服务客户端：

**TencentSSLHandler 关键方法：**
| 方法 | 功能 |
|---|---|
| `upload_certificate(cert_pem, key_pem)` | 上传证书到腾讯云（仅支持证书和私钥内容） |
| `get_certificate_list(limit, offset, search_key)` | 获取证书列表 |
| `get_certificate_by_domain(domain)` | 根据域名查询证书 |
| `get_certificate_id(domain)` | 根据域名获取证书 ID |
| `delete_certificate(cert_id)` | 删除证书 |
| `deploy_certificate(cert_id, resource_type, resource_ids, domain)` | 部署证书到云资源 |
| `deploy_to_cdn(cert_id, domain)` | 部署证书到 CDN |
| `deploy_to_clb(cert_id, listener_ids)` | 部署证书到负载均衡 |
| `update_certificate(old_cert_id, cert_pem, key_pem, alias)` | 更新证书内容 |
| `check_certificate_status(cert_id)` | 检查证书状态 |
| `replace_certificate(cert_id, resource_type, resource_ids)` | 替换资源的证书 |

**注意：** `UploadCertificate` API 仅支持 `CertificatePublicKey` 和 `CertificatePrivateKey` 两个参数，不支持 `CertificateAlias` 和 `CertificateNote`。

**支持的资源类型：**
`clb`, `cdn`, `waf`, `live`, `ddos`, `teo`, `apigateway`, `vod`, `tke`, `tcb`, `tse`, `cos`, `scf`

### API 接口

`index.py` 的 `main_handler` 支持三种触发方式：

- **定时触发器**：`check_and_renew()` - 自动续期即将过期证书
- **API 网关**：REST 接口
  - `POST /certificate/issue` - 申请新证书并上传到腾讯云
  - `POST /certificate/renew` - 续期证书
  - `POST /certificate/deploy` - 部署证书到云资源
  - `GET /certificate/list` - 列出证书
- **直接调用**：`{"action": "issue|renew|deploy|list|check|upload", ...}`

### 可用操作（Actions）

| Action | 功能 | 参数 |
|---|---|---|
| `issue` | 申请新证书并上传到腾讯云 | `domain`, `staging` |
| `issue-local` | 本地申请证书（不上传） | `domain`, `email`, `production`, `work-dir` |
| `renew` | 续期证书 | `domain`, `force` |
| `deploy` | 部署证书到云资源 | `domain`, `resourceType`, `resourceIds` |
| `list` | 列出证书 | `domain`（可选） |
| `check` | 检查并自动续期即将过期证书 | 无 |
| `upload` | 上传已有证书到腾讯云 | `domain`, `certDir`（可选） |

### 核心函数

| 函数 | 功能 |
|---|---|
| `issue_new_certificate(domain, staging)` | 申请证书并上传到腾讯云 SSL 服务 |
| `issue_certificate_local(domain, email, staging, work_dir)` | 本地申请证书，保存到 `./certs/{domain}/` |
| `renew_certificate(domain, force)` | 续期证书 |
| `deploy_certificate(domain, resource_type, resource_ids)` | 部署证书到云资源 |
| `list_certificates(domain)` | 列出证书 |
| `upload_existing_certificate(domain, cert_dir)` | 上传已有证书到腾讯云 |
| `check_and_renew()` | 定时任务入口，检查并自动续期 |

## 开发命令

```bash
# 安装依赖
pip install -r requirements.txt

# 运行测试
python test.py

# 证书管理命令
python index.py issue-local cdn.example.com              # 本地申请证书（测试环境）
python index.py issue-local cdn.example.com --email user@example.com  # 指定邮箱
python index.py issue-local cdn.example.com --production # 使用生产环境
python index.py issue cdn.example.com                    # 申请并上传到腾讯云
python index.py upload cdn.example.com                  # 上传已有证书到腾讯云
python index.py renew cdn.example.com                    # 续期证书
python index.py renew cdn.example.com --force            # 强制续期
python index.py list                                      # 列出证书
python index.py check                                     # 检查并续期即将过期的证书

# 创建部署包
./deploy.sh package   # Windows 使用 ./deploy.ps1
```

## 重要说明

### 纯 Python 实现
- **无 acme.sh 依赖** - 使用 Certbot 官方的 `acme` 和 `josepy` 库
- 账户密钥存储：`/tmp/acme/account_key.pem`（SCF 环境）
- 证书存储位置：
  - **SCF 环境**：`/tmp/acme/{domain}/fullchain.pem` 和 `privkey.pem`
  - **本地开发**：`./certs/{domain}/fullchain.pem` 和 `privkey.pem`

### DNS 挑战处理器
- `dns_challenge.py` 提供 `DNSChallengeCallback` 适配器
- 集成 `DNSPodV3Handler`（使用 2021-03-23 API 版本，TC3-HMAC-SHA256 签名）
- 自动从 `_acme-challenge.sub.example.com` 提取主域名

### SCF 环境约束
- **超时限制**：SCF 最大 300 秒，典型证书申请需 40-90 秒
- **工作目录**：使用 `/tmp/acme` 存储临时文件
- **冷启动**：首次运行会生成账户密钥，缓存在 `/tmp/acme/`

### Let's Encrypt 限制
- 生产环境：每周每域名最多 5 个证书
- 测试环境（staging）：无限制（设置 `ACME_STAGING=true` 或参数 `staging=true`）
- 建议设置 `ACME_ACCOUNT_EMAIL` 环境变量以接收证书过期提醒

### 腾讯云 SDK 使用规范
使用腾讯云 SDK 时，**必须**参考官方 API 文档获取请求和返回字段的具体格式：
- SSL 证书服务：https://cloud.tencent.com/document/product/400/41681
- DNSPod API：https://cloud.tencent.com/document/product/1427/56194

**关键要点：**
- 使用 `getattr(obj, 'field', default)` 安全访问字段，避免 API 返回格式变化导致异常
- SDK 返回的对象属性需要转换为字典才能 JSON 序列化
- `Credential` 从 `tencentcloud.common.credential` 导入，不是各服务的 models 模块

## 配置说明

必需的环境变量（在 SCF 控制台或本地 `.env` 文件配置）：
- `TENCENT_SECRET_ID`、`TENCENT_SECRET_KEY` - 腾讯云凭据（用于 DNSPod V3 API 和 SSL 证书服务）
- `TENCENT_REGION` - 默认：`ap-guangzhou`

可选配置：
- `ACME_ACCOUNT_EMAIL` - 默认：`admin@example.com`
- `ACME_HOME_DIR` - 默认：`/tmp/acme`
- `ACME_DNS_PROPAGATION` - DNS 传播等待时间（秒），默认：`60`
- `ACME_STAGING` - 使用 Let's Encrypt 测试环境，默认：`false`
- `NOTIFY_ENABLED`、`NOTIFY_WEBHOOK` - Webhook 通知
