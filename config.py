"""
配置管理模块
管理环境变量和应用配置
"""
import os
from typing import Optional


class Config:
    """应用配置类"""

    # 腾讯云 API 配置（用于 DNSPod V3 API 和 SSL 证书服务）
    TENCENT_SECRET_ID: Optional[str] = os.environ.get('TENCENT_SECRET_ID')
    TENCENT_SECRET_KEY: Optional[str] = os.environ.get('TENCENT_SECRET_KEY')
    TENCENT_REGION: str = os.environ.get('TENCENT_REGION', 'ap-guangzhou')

    # ACME 配置
    ACME_SERVER: str = os.environ.get('ACME_SERVER', 'letsencrypt')
    ACME_STAGING: bool = os.environ.get('ACME_STAGING', 'false').lower() == 'true'
    ACME_HOME_DIR: str = os.environ.get('ACME_HOME_DIR', '/tmp/acme')
    ACME_ACCOUNT_EMAIL: str = os.environ.get('ACME_ACCOUNT_EMAIL', 'admin@example.com')
    ACME_DNS_PROPAGATION: int = int(os.environ.get('ACME_DNS_PROPAGATION', '60'))

    # 证书配置
    CERT_KEY_SIZE: int = int(os.environ.get('CERT_KEY_SIZE', '2048'))
    CERT_VALID_DAYS: int = int(os.environ.get('CERT_VALID_DAYS', '90'))
    CERT_EXPIRY_WARNING_DAYS: int = int(os.environ.get('CERT_EXPIRY_WARNING_DAYS', '30'))

    # 通知配置
    NOTIFY_ENABLED: bool = os.environ.get('NOTIFY_ENABLED', 'false').lower() == 'true'
    NOTIFY_WEBHOOK: Optional[str] = os.environ.get('NOTIFY_WEBHOOK')

    @classmethod
    def validate(cls) -> tuple[bool, list[str]]:
        """验证配置完整性"""
        errors = []

        if not cls.TENCENT_SECRET_ID:
            errors.append('TENCENT_SECRET_ID is required')
        if not cls.TENCENT_SECRET_KEY:
            errors.append('TENCENT_SECRET_KEY is required')

        return len(errors) == 0, errors


class AcmeConfig:
    """ACME 协议相关配置（纯 Python 实现）"""

    # Let's Encrypt API 端点
    LETSENCRYPT_PRODUCTION = 'https://acme-v02.api.letsencrypt.org/directory'
    LETSENCRYPT_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'

    # 证书相关路径
    CERT_FILE = 'fullchain.pem'
    KEY_FILE = 'privkey.pem'
    CA_FILE = 'chain.pem'
    FULLCHAIN_FILE = 'fullchain.pem'

    # DNS 验证相关
    DNS_PROPAGATION_TIMEOUT = 120  # 秒
    DNS_PROPAGATION_CHECK_INTERVAL = 5  # 秒

    # 轮询配置
    POLL_INTERVAL = 3  # 秒
    POLL_MAX_ATTEMPTS = 30

    @classmethod
    def get_cert_dir(cls, domain: str) -> str:
        """获取证书存储目录"""
        return f'{Config.ACME_HOME_DIR}/{domain}'

    @classmethod
    def get_cert_path(cls, domain: str) -> str:
        """获取证书文件路径"""
        return f'{cls.get_cert_dir(domain)}/{cls.CERT_FILE}'

    @classmethod
    def get_key_path(cls, domain: str) -> str:
        """获取私钥文件路径"""
        return f'{cls.get_cert_dir(domain)}/{cls.KEY_FILE}'
