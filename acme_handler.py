"""
ACME 证书申请模块（纯 Python 实现）
使用 PureACMEClient 申请 Let's Encrypt 证书
"""
import logging
import os
from typing import Optional, Tuple, Dict, Any, List

from config import Config, AcmeConfig
from acme_client import PureACMEClient, ACMEConfig as ClientACMEConfig
from dns_challenge import create_dns_challenge_handler

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AcmeCertificateHandler:
    """ACME 证书申请处理器（纯 Python 实现）"""

    def __init__(self, work_dir: str = '/tmp/acme'):
        """
        初始化 ACME 处理器

        Args:
            work_dir: 工作目录
        """
        self.work_dir = work_dir
        ClientACMEConfig.WORK_DIR = work_dir

        # 创建 DNS 挑战处理器
        # DNSPodV3Handler 使用腾讯云 API 凭据（通过官方 SDK）
        self.dns_callback = create_dns_challenge_handler(
            secret_id=Config.TENCENT_SECRET_ID or '',
            secret_key=Config.TENCENT_SECRET_KEY or '',
            region=Config.TENCENT_REGION
        )

        # ACME 客户端（延迟初始化）
        self._acme_client: Optional[PureACMEClient] = None

    def _get_acme_client(self, staging: bool = False) -> PureACMEClient:
        """
        获取或创建 ACME 客户端

        Args:
            staging: 是否使用测试环境

        Returns:
            ACME 客户端
        """
        if self._acme_client is None or self._acme_client.staging != staging:
            email = os.environ.get('ACME_ACCOUNT_EMAIL', 'admin@example.com')
            self._acme_client = PureACMEClient(
                email=email,
                staging=staging,
                work_dir=self.work_dir
            )
        return self._acme_client

    def is_ready(self, require_ssl: bool = False) -> bool:
        """
        检查处理器是否准备就绪

        Args:
            require_ssl: 是否需要 SSL 服务凭据（用于上传到腾讯云）

        Returns:
            是否准备就绪
        """
        # DNS 验证需要腾讯云 API 凭据
        has_dns_creds = bool(Config.TENCENT_SECRET_ID and Config.TENCENT_SECRET_KEY)
        if not require_ssl:
            return has_dns_creds
        # SSL 服务需要同样的凭据
        return has_dns_creds

    def issue_certificate(
        self,
        domain: str,
        staging: bool = False,
        domains: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        申请证书

        Args:
            domain: 主域名
            staging: 是否使用测试环境
            domains: 额外的域名列表（用于 SAN 证书）

        Returns:
            申请结果
        """
        logger.info(f'Starting certificate issuance for {domain}')

        # 检查配置
        if not self.is_ready():
            return {
                'success': False,
                'message': 'DNSPod credentials not configured'
            }

        # 构建域名列表
        domain_list = [domain]
        if domains:
            domain_list.extend([d for d in domains if d != domain])

        # 去重
        domain_list = list(dict.fromkeys(domain_list))

        try:
            # 获取 ACME 客户端
            acme_client = self._get_acme_client(staging)

            # 申请证书
            result = acme_client.request_certificate(
                domains=domain_list,
                dns_record_callback=self.dns_callback.add_record,
                dns_cleanup_callback=self.dns_callback.cleanup_record,
                dns_propagation_seconds=int(os.environ.get('ACME_DNS_PROPAGATION', '60'))
            )

            # 添加证书路径信息
            if result.get('success'):
                result['cert_path'] = ClientACMEConfig.get_cert_path(domain)
                result['key_path'] = ClientACMEConfig.get_key_path(domain)
                result['staging'] = staging
                logger.info(f'Certificate issued successfully for {domain}')
            else:
                logger.error(f'Certificate issuance failed for {domain}: {result.get("message")}')

            return result

        except Exception as e:
            logger.error(f'Certificate issuance error for {domain}: {e}')
            return {
                'success': False,
                'message': f'Certificate issuance failed: {str(e)}'
            }

    def get_certificate(self, domain: str) -> Tuple[Optional[str], Optional[str]]:
        """
        获取证书内容

        Args:
            domain: 域名

        Returns:
            (证书内容, 私钥内容)
        """
        acme_client = self._get_acme_client()
        return acme_client.get_certificate(domain)

    def renew_certificate(self, domain: str, force: bool = False) -> Dict[str, Any]:
        """
        续期证书

        Args:
            domain: 域名
            force: 是否强制续期

        Returns:
            续期结果
        """
        logger.info(f'Renewing certificate for {domain} (force={force})')

        # 检查是否需要续期
        if not force:
            expiry_info = self.check_certificate_expiry(domain)
            if expiry_info and not expiry_info['is_expiring_soon']:
                logger.info(f'Certificate for {domain} is still valid')
                return {
                    'success': True,
                    'domain': domain,
                    'message': f'Certificate is still valid, expires in {expiry_info["remaining_days"]} days',
                    'skipped': True
                }

        # 续期证书（实际上是重新申请）
        return self.issue_certificate(domain)

    def revoke_certificate(self, domain: str) -> Dict[str, Any]:
        """
        撤销证书

        Args:
            domain: 域名

        Returns:
            撤销结果
        """
        logger.info(f'Revoking certificate for {domain}')

        try:
            cert_pem, _ = self.get_certificate(domain)
            if not cert_pem:
                return {
                    'success': False,
                    'message': 'Certificate not found'
                }

            acme_client = self._get_acme_client()
            success = acme_client.revoke_certificate(cert_pem)

            if success:
                return {
                    'success': True,
                    'domain': domain,
                    'message': 'Certificate revoked successfully'
                }
            else:
                return {
                    'success': False,
                    'message': 'Certificate revocation failed'
                }

        except Exception as e:
            logger.error(f'Certificate revocation error for {domain}: {e}')
            return {
                'success': False,
                'message': f'Certificate revocation failed: {str(e)}'
            }

    def remove_certificate(self, domain: str) -> Dict[str, Any]:
        """
        删除本地证书（不撤销）

        Args:
            domain: 域名

        Returns:
            删除结果
        """
        logger.info(f'Removing certificate for {domain}')

        import shutil

        cert_dir = ClientACMEConfig.get_cert_dir(domain)

        try:
            if os.path.exists(cert_dir):
                shutil.rmtree(cert_dir)
                logger.info(f'Certificate directory removed: {cert_dir}')
                return {
                    'success': True,
                    'domain': domain,
                    'message': 'Certificate removed successfully'
                }
            else:
                return {
                    'success': False,
                    'message': 'Certificate not found'
                }

        except Exception as e:
            logger.error(f'Certificate removal error for {domain}: {e}')
            return {
                'success': False,
                'message': f'Certificate removal failed: {str(e)}'
            }

    def list_certificates(self) -> List[Dict[str, Any]]:
        """
        列出所有证书

        Returns:
            证书列表
        """
        import os
        from datetime import datetime

        work_dir = ClientACMEConfig.WORK_DIR
        certs = []

        if not os.path.exists(work_dir):
            return certs

        for domain_dir in os.listdir(work_dir):
            cert_path = os.path.join(work_dir, domain_dir, 'fullchain.pem')
            key_path = os.path.join(work_dir, domain_dir, 'privkey.pem')

            if os.path.exists(cert_path) and os.path.exists(key_path):
                # 获取文件修改时间作为创建时间
                create_time = datetime.fromtimestamp(
                    os.path.getmtime(cert_path)
                ).strftime('%Y-%m-%d %H:%M:%S')

                certs.append({
                    'domain': domain_dir,
                    'key_length': '2048',
                    'create_time': create_time,
                    'cert_path': cert_path,
                    'key_path': key_path,
                })

        return certs

    def check_certificate_expiry(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        检查证书有效期

        Args:
            domain: 域名

        Returns:
            证书有效期信息，如果证书不存在返回 None
        """
        cert_path = ClientACMEConfig.get_cert_path(domain)

        if not os.path.exists(cert_path):
            return None

        try:
            from OpenSSL import crypto

            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

            # 获取过期时间
            expiry_str = cert.get_notAfter().decode('utf-8')
            from datetime import datetime, timezone
            expiry_date = datetime.strptime(expiry_str, '%Y%m%d%H%M%SZ')
            remaining = expiry_date - datetime.now(timezone.utc)

            return {
                'domain': domain,
                'expiry_date': expiry_date.isoformat(),
                'remaining_days': remaining.days,
                'is_expiring_soon': remaining.days < Config.CERT_EXPIRY_WARNING_DAYS,
                'is_expired': remaining.days <= 0,
            }
        except Exception as e:
            logger.error(f'Error checking certificate expiry: {e}')
            return None


# 兼容性：保留旧的类名
AcmeHandler = AcmeCertificateHandler


class AcmeCertificateInfo:
    """证书信息工具类"""

    @staticmethod
    def parse_cert_info(cert_pem: str) -> Dict[str, Any]:
        """
        解析证书信息

        Args:
            cert_pem: 证书内容（PEM 格式）

        Returns:
            证书信息
        """
        from OpenSSL import crypto
        from datetime import datetime

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

        # 获取主题
        subject = cert.get_subject()
        components = dict(subject.get_components())

        # 获取 SAN (Subject Alternative Names)
        san_names = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                san_str = str(ext)
                # 解析 SAN 字符串
                for name in san_str.split(', '):
                    if name.startswith('DNS:'):
                        san_names.append(name[4:])

        # 获取有效期
        not_before = datetime.strptime(cert.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
        not_after = datetime.strptime(cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')

        return {
            'subject': components,
            'issuer': dict(cert.get_issuer().get_components()),
            'common_name': components.get(b'CN', b'').decode('utf-8'),
            'san_names': san_names,
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'serial_number': cert.get_serial_number(),
            'version': cert.get_version(),
            'signature_algorithm': cert.get_signature_algorithm().decode('utf-8'),
        }

    @staticmethod
    def validate_cert_key_pair(cert_pem: str, key_pem: str) -> bool:
        """
        验证证书和私钥是否匹配

        Args:
            cert_pem: 证书内容
            key_pem: 私钥内容

        Returns:
            是否匹配
        """
        from OpenSSL import crypto

        try:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)

            # 简单验证：检查公钥是否一致
            cert_pubkey = cert.get_pubkey()
            key_pubkey = key

            # 检查密钥位数
            if cert_pubkey.bits() != key_pubkey.bits():
                return False

            # 检查公钥字节数据
            cert_bytes = cert_pubkey.to_bytes(key_pubkey.bits() // 8, 'big')
            key_bytes = key_pubkey.to_bytes(key_pubkey.bits() // 8, 'big')

            return cert_bytes == key_bytes

        except Exception:
            return False
