"""
Pure Python ACME Client Implementation
使用 Certbot 官方的 acme 和 josepy 库实现 Let's Encrypt ACMEv2 协议
"""
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

try:
    from acme import client, messages, challenges, errors
    from acme.jose import JWKRSA, JWK
    from acme import crypto_util
except ImportError:
    raise ImportError(
        'acme library is required. '
        'Install it with: pip install acme'
    )

logger = logging.getLogger(__name__)


class ACMEConfig:
    """ACME 协议配置"""

    # Let's Encrypt API 端点
    PRODUCTION_URL = 'https://acme-v02.api.letsencrypt.org/directory'
    STAGING_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'

    # 证书配置
    DEFAULT_KEY_SIZE = 2048
    CERT_VALIDITY_DAYS = 90

    # 超时配置
    POLL_INTERVAL = 3  # 秒
    POLL_MAX_ATTEMPTS = 30
    DNS_PROPAGATION_TIMEOUT = 120  # 秒

    # 工作目录
    WORK_DIR = '/tmp/acme'

    @classmethod
    def get_directory_url(cls, staging: bool = False) -> str:
        """
        获取 ACME 目录 URL

        Args:
            staging: 是否使用测试环境

        Returns:
            ACME 目录 URL
        """
        return cls.STAGING_URL if staging else cls.PRODUCTION_URL

    @classmethod
    def get_account_key_path(cls) -> str:
        """获取账户密钥路径"""
        return os.path.join(cls.WORK_DIR, 'account_key.pem')

    @classmethod
    def get_cert_dir(cls, domain: str) -> str:
        """获取证书存储目录"""
        return os.path.join(cls.WORK_DIR, domain)

    @classmethod
    def get_cert_path(cls, domain: str) -> str:
        """获取证书文件路径"""
        return os.path.join(cls.get_cert_dir(domain), 'fullchain.pem')

    @classmethod
    def get_key_path(cls, domain: str) -> str:
        """获取私钥文件路径"""
        return os.path.join(cls.get_cert_dir(domain), 'privkey.pem')


class ACMEAccount:
    """ACME 账户管理"""

    def __init__(self, email: str = '', work_dir: str = ACMEConfig.WORK_DIR):
        """
        初始化账户管理器

        Args:
            email: 账户邮箱
            work_dir: 工作目录
        """
        self.email = email or 'admin@example.com'
        self.work_dir = work_dir
        self.key_path = os.path.join(work_dir, 'account_key.pem')
        self.key = None
        self.jwk = None

    def _load_or_create_key(self) -> JWKRSA:
        """
        加载或创建账户密钥

        Returns:
            JWK RSA 密钥
        """
        # 确保工作目录存在
        os.makedirs(self.work_dir, exist_ok=True)

        # 尝试加载现有密钥
        if os.path.exists(self.key_path):
            logger.info(f'Loading existing account key from {self.key_path}')
            with open(self.key_path, 'rb') as f:
                key_data = f.read()
                private_key = serialization.load_pem_private_key(
                    key_data,
                    password=None,
                    backend=default_backend()
                )
                self.key = private_key
        else:
            # 创建新密钥
            logger.info('Creating new ACME account key')
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.key = private_key

            # 保存密钥
            with open(self.key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

        # 创建 JWK
        self.jwk = JWKRSA(key=self.key)
        return self.jwk

    def register_or_recover(
        self,
        acme_client: client.ClientV2,
        staging: bool = False
    ) -> messages.RegistrationResource:
        """
        注册或恢复 ACME 账户

        Args:
            acme_client: ACME 客户端
            staging: 是否使用测试环境

        Returns:
            注册资源
        """
        # 确保密钥已加载
        if self.jwk is None:
            self._load_or_create_key()

        # 创建注册请求
        regr = messages.NewRegistration.from_data(
            email=self.email,
            terms_of_service_agreed=True
        )

        try:
            # 尝试注册
            logger.info(f'Registering ACME account with email: {self.email}')
            registration = acme_client.new_account(regr)
            logger.info('ACME account registered successfully')
            return registration
        except errors.ConflictError as e:
            # 账户已存在（ConflictError 表示密钥已注册）
            # e.location 包含账户 URL
            account_url = e.location
            logger.info(f'Account already exists with this key, account URL: {account_url}')

            # 更新网络层的账户 URL（作为 Key ID）
            acme_client.net.account_url = account_url

            # 创建一个基本的注册资源，包含账户 URL
            registration = messages.RegistrationResource(
                uri=account_url,
                body=regr
            )
            logger.info('Account recovered successfully with account URL')
            return registration
        except messages.Error as e:
            if e.code == 'urn:ietf:params:acme:error:accountDoesNotExist':
                # 账户不存在，需要创建新账户
                raise
            elif e.code == 'urn:ietf:params:acme:error:alreadyRegistered':
                # 账户已注册，尝试恢复
                logger.info('Account already registered, recovering...')
                try:
                    registration = acme_client.query_registration(regr)
                    logger.info('Account recovered successfully')
                    return registration
                except Exception:
                    # 如果恢复失败，创建新密钥并重新注册
                    logger.info('Recovery failed, creating new account key...')
                    os.remove(self.key_path)
                    self._load_or_create_key()
                    # 重新创建客户端网络
                    jwk = self.jwk
                    net = client.ClientNetwork(jwk, user_agent='tencent-ssl-cert-manager/1.0')
                    directory_url = ACMEConfig.get_directory_url(self.staging)
                    directory = client.ClientV2.get_directory(directory_url, net)
                    acme_client.__init__(directory, net=net)
                    registration = acme_client.new_account(regr)
                    return registration
            else:
                raise


class ACMEOrder:
    """ACME 订单管理"""

    def __init__(self, acme_client: client.ClientV2):
        """
        初始化订单管理器

        Args:
            acme_client: ACME 客户端
        """
        self.client = acme_client

    def create_order(
        self,
        domains: List[str],
        csr_pem: bytes,
        staging: bool = False
    ) -> messages.OrderResource:
        """
        创建证书订单（新 API: new_order 需要 CSR）

        Args:
            domains: 域名列表
            csr_pem: CSR 证书签名请求（PEM 格式字节）
            staging: 是否使用测试环境

        Returns:
            订单资源
        """
        logger.info(f'Creating ACME order for domains: {domains}')

        # 新版 API: new_order 需要 CSR 作为参数
        order = self.client.new_order(csr_pem)
        logger.info(f'Order created: {order.uri}')
        return order

    def poll_order(
        self,
        order: messages.OrderResource,
        timeout: int = 180
    ) -> messages.OrderResource:
        """
        轮询订单状态

        Args:
            order: 订单资源
            timeout: 超时时间（秒）

        Returns:
            最终订单资源
        """
        start_time = time.time()
        deadline = order.body.update_deadline

        while time.time() - start_time < timeout:
            # 更新订单状态
            order = self.client.poll(order)

            if order.body.status == messages.STATUS_VALID:
                logger.info('Order is valid')
                return order
            elif order.body.status == messages.STATUS_INVALID:
                logger.error(f'Order is invalid: {order.body.error}')
                raise Exception(f'Order failed: {order.body.error}')
            elif order.body.status == messages.STATUS_READY:
                logger.info('Order is ready for finalization')
                return order
            elif order.body.status in (messages.STATUS_PENDING, messages.STATUS_PROCESSING):
                logger.info(f'Order status: {order.body.status}, waiting...')
                time.sleep(ACMEConfig.POLL_INTERVAL)
            else:
                logger.warning(f'Unknown order status: {order.body.status}')
                time.sleep(ACMEConfig.POLL_INTERVAL)

        raise Exception(f'Order polling timeout after {timeout} seconds')

    def finalize_order(
        self,
        order: messages.OrderResource,
        deadline: float = None
    ) -> messages.OrderResource:
        """
        完成订单（使用 poll_and_finalize）

        Args:
            order: 订单资源
            deadline: 截止时间戳

        Returns:
            完成后的订单资源
        """
        logger.info('Finalizing order with poll_and_finalize')

        if deadline is None:
            deadline = time.time() + 300

        # 使用新 API: poll_and_finalize
        finalized_order = self.client.poll_and_finalize(
            order,
            deadline=datetime.fromtimestamp(deadline)
        )

        logger.info('Order finalized successfully')
        return finalized_order


class DNS01Challenge:
    """DNS-01 挑战处理"""

    def __init__(self, acme_client: client.ClientV2, account_jwk: JWKRSA):
        """
        初始化 DNS-01 挑战处理器

        Args:
            acme_client: ACME 客户端
            account_jwk: 账户 JWK 密钥
        """
        self.client = acme_client
        self.account_jwk = account_jwk

    def get_dns_challenges(
        self,
        order: messages.OrderResource
    ) -> List[Tuple[messages.AuthorizationResource, challenges.ChallengeBody]]:
        """
        获取 DNS 挑战

        Args:
            order: 订单资源

        Returns:
            (授权资源, 挑战体) 列表
        """
        dns_challenges = []

        for authz in order.authorizations:
            # 新 API: order.authorizations 已经是完整的 AuthorizationResource 对象
            # 不需要额外查询
            logger.info(f'Processing authorization for: {authz.body.identifier.value}')

            # 查找 DNS-01 挑战
            for challenge_body in authz.body.challenges:
                if isinstance(challenge_body.chall, challenges.DNS01):
                    dns_challenges.append((authz, challenge_body))
                    logger.info(f'Found DNS-01 challenge for {authz.body.identifier.value}')
                    break
            else:
                logger.warning(f'No DNS-01 challenge found for {authz.body.identifier.value}')

        return dns_challenges

    def get_validation_record(self, authz: messages.AuthorizationResource) -> Tuple[str, str]:
        """
        获取 DNS 验证记录

        Args:
            authz: 授权资源

        Returns:
            (记录名, 记录值) 元组
        """
        domain = authz.body.identifier.value

        # 查找 DNS-01 挑战
        for challenge_body in authz.body.challenges:
            if isinstance(challenge_body.chall, challenges.DNS01):
                # DNS-01 验证记录名称
                record_name = challenge_body.chall.validation_domain_name(domain)

                # 使用 acme 库的方法计算验证值（base64url 编码的 SHA256 哈希）
                record_value = challenge_body.chall.validation(self.account_jwk)

                logger.info(f'DNS validation record: {record_name} -> {record_value}')

                return record_name, record_value

        raise Exception(f'No DNS-01 challenge found for {domain}')

    def answer_challenge(self, challenge_body: challenges.ChallengeBody) -> messages.ChallengeResource:
        """
        回答挑战

        Args:
            challenge_body: 挑战体

        Returns:
            挑战资源
        """
        logger.info(f'Answering challenge: {challenge_body.uri}')

        # 生成挑战响应
        response = challenge_body.chall.response(self.account_jwk)

        # 回答挑战
        return self.client.answer_challenge(challenge_body, response)

    def poll_authorization(
        self,
        authz: messages.AuthorizationResource,
        timeout: int = 120
    ) -> messages.AuthorizationResource:
        """
        轮询授权状态

        Args:
            authz: 授权资源
            timeout: 超时时间（秒）

        Returns:
            最终授权资源
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            # 更新授权状态 (poll 返回 tuple: (authz, response))
            authz, _ = self.client.poll(authz)

            if authz.body.status == messages.STATUS_VALID:
                logger.info(f'Authorization valid for {authz.body.identifier.value}')
                return authz
            elif authz.body.status == messages.STATUS_INVALID:
                error = authz.body.challenges[0].error if authz.body.challenges else None
                logger.error(f'Authorization invalid for {authz.body.identifier.value}: {error}')
                raise Exception(f'Authorization failed: {error}')
            elif authz.body.status in (messages.STATUS_PENDING, messages.STATUS_PROCESSING):
                logger.info(f'Authorization status: {authz.body.status}, waiting...')
                time.sleep(ACMEConfig.POLL_INTERVAL)
            else:
                logger.warning(f'Unknown authorization status: {authz.body.status}')
                time.sleep(ACMEConfig.POLL_INTERVAL)

        raise Exception(f'Authorization polling timeout after {timeout} seconds')


class CertificateManager:
    """证书管理器"""

    @staticmethod
    def generate_private_key(key_size: int = ACMEConfig.DEFAULT_KEY_SIZE) -> rsa.RSAPrivateKey:
        """
        生成 RSA 私钥

        Args:
            key_size: 密钥大小

        Returns:
            RSA 私钥对象
        """
        logger.info(f'Generating {key_size}-bit RSA private key')
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

    @staticmethod
    def generate_csr(
        domain: str,
        sans: List[str] = None,
        key: rsa.RSAPrivateKey = None
    ) -> bytes:
        """
        生成证书签名请求 (CSR)

        Args:
            domain: 主域名
            sans: 主题备用名称列表
            key: 私钥（如果不提供则生成新密钥）

        Returns:
            CSR PEM 格式字节
        """
        if key is None:
            key = CertificateManager.generate_private_key()

        logger.info(f'Generating CSR for {domain}, SANs: {sans or []}')

        # 构建 CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Example Inc'),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ]))

        # 添加 SAN 扩展
        all_domains = [domain]
        if sans:
            all_domains.extend(sans)

        san_names = [x509.DNSName(d) for d in all_domains]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False
        )

        # 签名 CSR
        csr = builder.sign(
            private_key=key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        return csr.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def key_to_pem(key: rsa.RSAPrivateKey) -> str:
        """
        私钥转 PEM 格式

        Args:
            key: RSA 私钥对象

        Returns:
            PEM 格式字符串
        """
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

    @staticmethod
    def cert_to_pem(cert: x509.Certificate) -> str:
        """
        证书转 PEM 格式

        Args:
            cert: 证书对象

        Returns:
            PEM 格式字符串
        """
        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    @staticmethod
    def save_certificate_and_key(
        cert_pem: str,
        key_pem: str,
        domain: str,
        work_dir: str = ACMEConfig.WORK_DIR,
        csr_pem: bytes = None
    ) -> Tuple[str, str]:
        """
        保存证书和私钥

        Args:
            cert_pem: 证书 PEM 内容
            key_pem: 私钥 PEM 内容
            domain: 域名
            work_dir: 工作目录
            csr_pem: CSR PEM 内容（可选）

        Returns:
            (证书路径, 私钥路径)
        """
        cert_dir = os.path.join(work_dir, domain)
        os.makedirs(cert_dir, exist_ok=True)

        cert_path = os.path.join(cert_dir, 'fullchain.pem')
        key_path = os.path.join(cert_dir, 'privkey.pem')
        csr_path = os.path.join(cert_dir, 'cert.csr')

        with open(cert_path, 'w') as f:
            f.write(cert_pem)

        with open(key_path, 'w') as f:
            f.write(key_pem)

        # 保存 CSR
        if csr_pem:
            with open(csr_path, 'wb') as f:
                f.write(csr_pem)
            logger.info(f'CSR saved to {csr_path}')

        logger.info(f'Certificate saved to {cert_path}')
        logger.info(f'Private key saved to {key_path}')

        return cert_path, key_path


class PureACMEClient:
    """
    纯 Python ACME 客户端
    统一接口，提供完整的证书申请流程
    """

    def __init__(
        self,
        email: str = '',
        staging: bool = False,
        work_dir: str = ACMEConfig.WORK_DIR
    ):
        """
        初始化 ACME 客户端

        Args:
            email: 账户邮箱
            staging: 是否使用测试环境
            work_dir: 工作目录
        """
        self.email = email or 'admin@example.com'
        self.staging = staging
        self.work_dir = work_dir
        ACMEConfig.WORK_DIR = work_dir

        # 初始化子模块
        self.account = ACMEAccount(email, work_dir)
        self.acme_client = None
        self.order_manager = None
        self.challenge_handler = None

    def _initialize_client(self):
        """初始化 ACME 客户端连接"""
        if self.acme_client is not None:
            return

        # 加载或创建账户密钥
        jwk = self.account._load_or_create_key()

        # 创建 ACME 客户端
        directory_url = ACMEConfig.get_directory_url(self.staging)
        logger.info(f'Using ACME directory: {directory_url}')

        # 创建目录客户端（初始不带账户信息）
        net = client.ClientNetwork(jwk, user_agent='tencent-ssl-cert-manager/1.0')
        directory = client.ClientV2.get_directory(directory_url, net)
        self.acme_client = client.ClientV2(directory, net=net)

        # 注册或恢复账户
        registration = self.account.register_or_recover(self.acme_client, self.staging)

        # 更新网络层的账户信息（重要：用于后续请求的签名）
        net.account = registration
        logger.info(f'Network account updated: {registration.uri}')

        # 初始化订单和挑战处理器
        self.order_manager = ACMEOrder(self.acme_client)
        self.challenge_handler = DNS01Challenge(self.acme_client, jwk)

    def request_certificate(
        self,
        domains: List[str],
        dns_record_callback: callable,
        dns_cleanup_callback: callable = None,
        dns_propagation_seconds: int = 60
    ) -> Dict[str, Any]:
        """
        请求证书（完整流程）

        Args:
            domains: 域名列表
            dns_record_callback: DNS 记录添加回调
                函数签名: (record_name: str, record_value: str) -> bool
            dns_cleanup_callback: DNS 记录清理回调（可选）
                函数签名: (record_name: str, record_value: str) -> bool
            dns_propagation_seconds: DNS 传播等待时间（秒）

        Returns:
            结果字典
        """
        try:
            # 初始化客户端
            self._initialize_client()

            # 1. 生成私钥和 CSR（新版 API 需要在创建订单前提供 CSR）
            private_key = CertificateManager.generate_private_key()
            key_pem = CertificateManager.key_to_pem(private_key)
            csr_pem = CertificateManager.generate_csr(domains[0], domains[1:], private_key)

            # 2. 创建订单（传入 CSR）
            order = self.order_manager.create_order(domains, csr_pem, self.staging)

            # 3. 获取 DNS 挑战
            dns_challenges = self.challenge_handler.get_dns_challenges(order)

            if not dns_challenges:
                return {
                    'success': False,
                    'message': 'No DNS-01 challenges found'
                }

            # 4. 添加 DNS 验证记录
            added_records = []
            for authz, challenge_body in dns_challenges:
                record_name, record_value = self.challenge_handler.get_validation_record(authz)
                logger.info(f'Adding DNS record: {record_name} = {record_value}')

                # 调用回调添加 DNS 记录
                if dns_record_callback(record_name, record_value):
                    added_records.append((record_name, record_value, authz, challenge_body))
                else:
                    return {
                        'success': False,
                        'message': f'Failed to add DNS record: {record_name}'
                    }

            # 5. 等待 DNS 传播
            logger.info(f'Waiting {dns_propagation_seconds} seconds for DNS propagation...')
            time.sleep(dns_propagation_seconds)

            # 6. 回答挑战并等待授权
            try:
                for record_name, record_value, authz, challenge_body in added_records:
                    # 回答挑战
                    self.challenge_handler.answer_challenge(challenge_body)

                # 等待所有授权完成
                for record_name, record_value, authz, challenge_body in added_records:
                    self.challenge_handler.poll_authorization(authz)

                logger.info('All authorizations completed')

            except Exception as e:
                # 清理 DNS 记录
                if dns_cleanup_callback:
                    for record_name, record_value, _, _ in added_records:
                        try:
                            dns_cleanup_callback(record_name, record_value)
                        except Exception:
                            pass
                raise

            # 7. 清理 DNS 记录
            if dns_cleanup_callback:
                for record_name, record_value, _, _ in added_records:
                    try:
                        logger.info(f'Cleaning up DNS record: {record_name}')
                        dns_cleanup_callback(record_name, record_value)
                    except Exception as e:
                        logger.warning(f'Failed to cleanup DNS record {record_name}: {e}')

            # 8. 完成订单（使用 poll_and_finalize）
            logger.info('Finalizing order after all authorizations completed')
            finalized_order = self.order_manager.finalize_order(order)

            # 9. 下载证书
            if finalized_order.fullchain_pem:
                cert_pem = finalized_order.fullchain_pem
                logger.info(f'Received certificate for {domains[0]}')

                # 保存证书和私钥（包含 CSR）
                cert_path, key_path = CertificateManager.save_certificate_and_key(
                    cert_pem, key_pem, domains[0], self.work_dir, csr_pem
                )

                logger.info(f'Certificate issued successfully for {domains[0]}')
                logger.info(f'Certificate saved to: {cert_path}')
                logger.info(f'Private key saved to: {key_path}')

                return {
                    'success': True,
                    'domain': domains[0],
                    'domains': domains,
                    'cert_path': cert_path,
                    'key_path': key_path,
                    'csr_path': os.path.join(self.work_dir, domains[0], 'cert.csr'),
                    'cert_pem': cert_pem,
                    'key_pem': key_pem,
                    'message': 'Certificate issued successfully'
                }
            else:
                return {
                    'success': False,
                    'message': 'No certificate in finalized order'
                }

        except Exception as e:
            logger.error(f'Certificate request failed: {e}')
            import traceback
            logger.error(traceback.format_exc())
            return {
                'success': False,
                'message': f'Certificate request failed: {str(e)}'
            }

    def get_certificate(self, domain: str) -> Tuple[Optional[str], Optional[str]]:
        """
        获取已保存的证书和私钥

        Args:
            domain: 域名

        Returns:
            (证书内容, 私钥内容)
        """
        cert_path = ACMEConfig.get_cert_path(domain)
        key_path = ACMEConfig.get_key_path(domain)

        try:
            with open(cert_path, 'r') as f:
                cert_pem = f.read()
            with open(key_path, 'r') as f:
                key_pem = f.read()

            return cert_pem, key_pem
        except FileNotFoundError:
            return None, None

    def revoke_certificate(self, cert_pem: str) -> bool:
        """
        撤销证书

        Args:
            cert_pem: 证书 PEM 内容

        Returns:
            是否成功
        """
        try:
            self._initialize_client()

            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

            # 使用 acme 客户端撤销证书
            # 注意：需要完整的撤销流程实现
            logger.warning('Certificate revocation not fully implemented')
            return False

        except Exception as e:
            logger.error(f'Certificate revocation failed: {e}')
            return False
