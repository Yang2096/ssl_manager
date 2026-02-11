"""
工具模块
提供通用的辅助函数
"""
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class DomainParser:
    """域名解析工具"""

    @staticmethod
    def parse_domain(domain: str) -> Dict[str, str]:
        """
        解析域名

        Args:
            domain: 域名

        Returns:
            包含主域名和子域名的字典
        """
        parts = domain.split('.')

        if len(parts) < 2:
            raise ValueError(f'Invalid domain: {domain}')

        # 简单判断：如果是 www.example.com，主域名为 example.com
        # 如果是 *.example.com，主域名为 example.com
        if len(parts) >= 3 and parts[0] in ['*', 'www']:
            main_domain = '.'.join(parts[1:])
            sub_domain = parts[0]
        elif len(parts) == 2:
            main_domain = domain
            sub_domain = '@'
        else:
            # 尝试查找公共后缀
            public_suffixes = ['com', 'net', 'org', 'cn', 'co.uk', 'com.cn']
            for suffix in public_suffixes:
                if domain.endswith('.' + suffix):
                    suffix_parts = suffix.split('.')
                    main_domain = '.'.join(parts[-(len(suffix_parts) + 1):])
                    sub_domain = '.'.join(parts[:-len(suffix_parts) - 1])
                    break
            else:
                # 默认：最后两部分作为主域名
                main_domain = '.'.join(parts[-2:])
                sub_domain = '.'.join(parts[:-2]) if len(parts) > 2 else '@'

        return {
            'domain': domain,
            'main_domain': main_domain,
            'sub_domain': sub_domain,
        }

    @staticmethod
    def extract_domain_from_cert(cert_pem: str) -> List[str]:
        """
        从证书中提取域名列表

        Args:
            cert_pem: 证书内容

        Returns:
            域名列表
        """
        from OpenSSL import crypto

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        domains = []

        # 获取 Common Name
        subject = cert.get_subject()
        cn = subject.CN
        if cn:
            domains.append(cn)

        # 获取 Subject Alternative Names
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                san_str = str(ext)
                for name in san_str.split(', '):
                    if name.startswith('DNS:'):
                        domains.append(name[4:])

        return list(set(domains))

    @staticmethod
    def is_wildcard_domain(domain: str) -> bool:
        """
        判断是否为泛域名

        Args:
            domain: 域名

        Returns:
            是否为泛域名
        """
        return domain.startswith('*.')


class CertificateUtils:
    """证书工具类"""

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

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

        # 获取主题
        subject = cert.get_subject()
        components = {k.decode(): v.decode() for k, v in subject.get_components()}

        # 获取 SAN
        san_names = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'subjectAltName':
                san_str = str(ext)
                for name in san_str.split(', '):
                    if name.startswith('DNS:'):
                        san_names.append(name[4:])

        # 获取有效期
        not_before = datetime.strptime(cert.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
        not_after = datetime.strptime(cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
        remaining_days = (not_after - datetime.now(timezone.utc)).days

        # 获取颁发者
        issuer_components = {k.decode(): v.decode() for k, v in cert.get_issuer().get_components()}

        return {
            'common_name': components.get('CN', ''),
            'san_names': san_names,
            'organization': components.get('O', ''),
            'organizational_unit': components.get('OU', ''),
            'country': components.get('C', ''),
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'remaining_days': remaining_days,
            'is_expired': remaining_days <= 0,
            'is_expiring_soon': remaining_days <= Config.CERT_EXPIRY_WARNING_DAYS,
            'issuer': issuer_components.get('O', ''),
            'serial_number': hex(cert.get_serial_number())[2:].upper(),
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

            # 尝试用私钥验证证书签名
            # 简单方法：检查公钥的模数
            cert_pubkey = cert.get_pubkey()
            key_pubkey_bits = key.bits()
            cert_pubkey_bits = cert_pubkey.bits()

            if key_pubkey_bits != cert_pubkey_bits:
                return False

            # 更精确的验证：比较公钥
            cert_pubkey_bytes = cert_pubkey.to_bytes(key_pubkey_bits // 8, 'big')
            key_pubkey_bytes = key.to_bytes(key_pubkey_bits // 8, 'big')

            return cert_pubkey_bytes == key_pubkey_bytes

        except Exception as e:
            logger.error(f'Error validating cert/key pair: {e}')
            return False

    @staticmethod
    def get_cert_fingerprint(cert_pem: str) -> str:
        """
        获取证书指纹

        Args:
            cert_pem: 证书内容

        Returns:
            证书指纹（SHA256）
        """
        import hashlib
        from OpenSSL import crypto

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        return hashlib.sha256(der).hexdigest()

    @staticmethod
    def format_pem(content: str, pem_type: str = 'CERTIFICATE') -> str:
        """
        格式化 PEM 内容

        Args:
            content: 原始内容
            pem_type: PEM 类型（CERTIFICATE, PRIVATE KEY, 等）

        Returns:
            格式化后的 PEM
        """
        # 移除现有格式
        content = re.sub(r'-----BEGIN.*?-----', '', content)
        content = re.sub(r'-----END.*?-----', '', content)
        content = content.replace('\n', '').replace('\r', '').strip()

        # 每 64 字符换行
        lines = [content[i:i+64] for i in range(0, len(content), 64)]

        # 重新添加 PEM 头尾
        return f'-----BEGIN {pem_type}-----\n' + '\n'.join(lines) + '\n' + f'-----END {pem_type}-----\n'


class NotificationHandler:
    """通知处理器"""

    @staticmethod
    def send_notification(
        title: str,
        message: str,
        level: str = 'info',
        extra_data: Optional[Dict] = None
    ) -> bool:
        """
        发送通知

        Args:
            title: 通知标题
            message: 通知内容
            level: 级别 (info, warning, error)
            extra_data: 额外数据

        Returns:
            是否成功
        """
        from config import Config

        if not Config.NOTIFY_ENABLED or not Config.NOTIFY_WEBHOOK:
            logger.info('Notification disabled or webhook not configured')
            return False

        try:
            import requests

            payload = {
                'title': title,
                'message': message,
                'level': level,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }

            if extra_data:
                payload['data'] = extra_data

            response = requests.post(
                Config.NOTIFY_WEBHOOK,
                json=payload,
                timeout=10
            )
            response.raise_for_status()

            logger.info(f'Notification sent: {title}')
            return True

        except Exception as e:
            logger.error(f'Failed to send notification: {e}')
            return False

    @staticmethod
    def notify_success(domain: str, action: str, cert_id: str = '') -> bool:
        """通知成功"""
        return NotificationHandler.send_notification(
            title=f'Certificate {action} Success',
            message=f'Certificate for {domain} has been {action}ed successfully',
            level='info',
            extra_data={'domain': domain, 'certId': cert_id}
        )

    @staticmethod
    def notify_failure(domain: str, action: str, error: str) -> bool:
        """通知失败"""
        return NotificationHandler.send_notification(
            title=f'Certificate {action} Failed',
            message=f'Failed to {action} certificate for {domain}: {error}',
            level='error',
            extra_data={'domain': domain, 'error': error}
        )


class FileHelper:
    """文件操作辅助类"""

    @staticmethod
    def ensure_dir(path: str) -> str:
        """
        确保目录存在

        Args:
            path: 目录路径

        Returns:
            目录路径
        """
        os.makedirs(path, exist_ok=True)
        return path

    @staticmethod
    def read_file(path: str, default: str = '') -> str:
        """
        读取文件

        Args:
            path: 文件路径
            default: 默认值

        Returns:
            文件内容
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            return default
        except Exception as e:
            logger.error(f'Error reading file {path}: {e}')
            return default

    @staticmethod
    def write_file(path: str, content: str) -> bool:
        """
        写入文件

        Args:
            path: 文件路径
            content: 文件内容

        Returns:
            是否成功
        """
        try:
            FileHelper.ensure_dir(os.path.dirname(path))
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f'Error writing file {path}: {e}')
            return False

    @staticmethod
    def safe_delete(path: str) -> bool:
        """
        安全删除文件

        Args:
            path: 文件路径

        Returns:
            是否成功
        """
        try:
            if os.path.exists(path):
                os.remove(path)
            return True
        except Exception as e:
            logger.error(f'Error deleting file {path}: {e}')
            return False
