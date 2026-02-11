# SSL Certificate Manager - SCF Implementation

Let's Encrypt 自动证书申请和管理系统，部署在腾讯云云函数（SCF）上。

## 功能特性

- **自动申请证书**：通过打包的 acme.sh + DNS-01 验证方式自动申请 Let's Encrypt 证书
- **DNSPod 集成**：自动管理 DNS 验证记录
- **腾讯云 SSL 服务集成**：自动上传证书到腾讯云
- **多资源部署**：支持部署到 CDN、CLB、API 网关等云资源
- **自动续期**：定时检查证书有效期，自动续期即将过期的证书
- **Serverless 部署**：基于腾讯云 SCF 云函数
- **内置 acme.sh**：无需运行时下载，已打包 acme.sh 脚本

## 目录结构

```
scf/
├── index.py              # 云函数入口
├── acme_handler.py       # ACME 证书申请逻辑
├── dns_handler.py        # DNSPod API 封装
├── tencent_ssl.py        # 腾讯云 SSL API 封装
├── config.py             # 配置管理
├── utils.py              # 工具函数
├── requirements.txt      # Python 依赖
├── template.yaml         # SCF 部署模板
├── deploy.sh / deploy.ps1  # 部署脚本
├── test.py               # 测试脚本
├── .env.example          # 环境变量示例
├── .gitignore            # Git 忽略文件
├── acme_lib/             # 内置的 acme.sh 脚本
│   ├── acme.sh           # acme.sh 主脚本
│   └── dnsapi/           # DNS API 集成脚本
│       └── dns_dp.sh     # DNSPod API 脚本
└── README.md             # 本文档
```

## 环境变量配置

| 变量名 | 说明 | 示例 | 必需 |
|-------|------|-----|-----|
| TENCENT_SECRET_ID | 腾讯云密钥 ID | AKIDxxxxx | 是 |
| TENCENT_SECRET_KEY | 腾讯云密钥 Key | xxxxxxxx | 是 |
| TENCENT_REGION | 腾讯云地域 | ap-guangzhou | 否 |
| ACME_STAGING | 是否使用测试环境 | true/false | 否 |
| ACME_HOME_DIR | ACME 工作目录 | /tmp/acme | 否 |
| CERT_EXPIRY_WARNING_DAYS | 证书过期提醒阈值（天） | 30 | 否 |
| NOTIFY_ENABLED | 是否启用通知 | true/false | 否 |
| NOTIFY_WEBHOOK | 通知 Webhook URL | https://... | 否 |

## 本地测试

### 1. 安装依赖

```bash
cd scf
pip install -r requirements.txt
```

### 2. 设置环境变量

创建 `.env` 文件：

```bash
TENCENT_SECRET_ID=your-tencent-secret-id
TENCENT_SECRET_KEY=your-tencent-secret-key
ACME_STAGING=true  # 测试时使用 staging 环境
```

### 3. 运行测试

```bash
# 测试证书申请
python index.py issue example.com

# 测试证书续期
python index.py renew example.com

# 列出证书
python index.py list

# 检查续期
python index.py check
```

## 云函数部署

### 方式一：使用部署脚本

**Linux/macOS:**
```bash
cd scf
chmod +x deploy.sh
./deploy.sh package   # 创建部署包
```

**Windows:**
```powershell
cd scf
.\deploy.ps1 package  # 创建部署包
```

脚本会自动：
1. 检查环境变量
2. 验证 acme.sh 组件
3. 安装 Python 依赖
4. 复制代码文件
5. 打包成 `deployment_package.zip`

### 方式二：使用 Serverless Framework

1. 安装 Serverless Framework：

```bash
npm install -g serverless
```

2. 部署：

```bash
serverless deploy
```

### 方式三：手动上传

1. 按"方式一"创建部署包
2. 登录腾讯云控制台，进入云函数服务
3. 创建新函数，选择"从头开始"
4. 上传 `deployment_package.zip`
5. 配置环境变量

## API 接口

### 1. 申请证书

```
POST /certificate/issue
```

**请求参数：**
```json
{
  "domain": "example.com",
  "staging": false
}
```

**响应：**
```json
{
  "success": true,
  "message": "Certificate issued successfully",
  "data": {
    "domain": "example.com",
    "certificateId": "cert-xxxxx",
    "staging": false
  }
}
```

### 2. 续期证书

```
POST /certificate/renew
```

**请求参数：**
```json
{
  "domain": "example.com",
  "force": false
}
```

### 3. 部署证书

```
POST /certificate/deploy
```

**请求参数：**
```json
{
  "domain": "example.com",
  "resourceType": "cdn",
  "resourceIds": ["domain-id"]
}
```

### 4. 列出证书

```
GET /certificate/list?domain=example.com
```

## ACME 证书申请流程

```
1. 初始化 acme.sh 环境
   └── 使用内置的 acme.sh 脚本
   └── 设置环境变量

2. 注册账户 (Account Registration)
   └── 生成 ACME 账户密钥对
   └── 向 Let's Encrypt API 发送注册请求

3. 创建证书订单 (Create Order)
   └── 指定域名列表
   └── 获取授权列表

4. 域名验证 (DNS-01)
   └── 调用 DNSPod API 添加 TXT 记录
   └── 等待 DNS 传播
   └── Let's Encrypt 验证 TXT 记录
   └── 删除 TXT 记录

5. 生成并下载证书
   └── 生成 CSR
   └── 提交 CSR 签发
   └── 下载证书

6. 上传到腾讯云
   └── UploadCertificate
   └── 返回证书 ID
```

## 关于内置 acme.sh

本项目已将 `acme.sh` 脚本及其 DNSPod API 集成脚本打包到 `acme_lib/` 目录中：

- `acme_lib/acme.sh` - acme.sh 主脚本
- `acme_lib/dnsapi/dns_dp.sh` - DNSPod DNS API 集成

这样做的好处：
1. **无需网络下载**：在 SCF 环境中不需要从 GitHub 下载脚本
2. **版本固定**：使用已验证的稳定版本
3. **更快部署**：减少初始化时间
4. **离线可用**：不依赖外部网络连接

## 常见问题

### Q: DNS 验证失败？

A: 检查以下几点：
1. DNSPod API 凭据是否正确
2. 域名是否已托管在 DNSPod
3. DNS 解析是否正常

### Q: 证书申请频率限制？

A: Let's Encrypt 限制：
- 生产环境：每周每域名最多 5 个证书
- 测试环境（staging）：无限制

使用 `ACME_STAGING=true` 测试时不会消耗生产环境配额。

### Q: 云函数超时？

A: 证书申请可能需要 2-5 分钟，建议设置超时时间为 300 秒。

### Q: 如何更新 acme.sh 脚本？

A: 从 GitHub 下载最新版本并替换：
```bash
# 下载主脚本
curl -o acme_lib/acme.sh https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh

# 下载 DNSPod API 脚本
curl -o acme_lib/dnsapi/dns_dp.sh https://raw.githubusercontent.com/acmesh-official/acme.sh/master/dnsapi/dns_dp.sh
```

## 许可证

MIT License

acme.sh 脚本遵循 GPL v3 许可证: https://github.com/acmesh-official/acme.sh
