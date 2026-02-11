"""
腾讯云 SSL 服务 API 封装模块
提供证书上传、查询、部署等功能
"""
import json
from typing import Optional, Dict, Any, List
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.common.credential import Credential
from tencentcloud.ssl.v20191205 import ssl_client, models as ssl_models


class TencentSSLHandler:
    """腾讯云 SSL 服务客户端"""

    # 支持的资源类型
    RESOURCE_TYPES = [
        'clb',      # 负载均衡
        'cdn',      # 内容分发网络
        'waf',      # Web 应用防火墙
        'live',     # 云直播
        'ddos',     # DDoS 防护
        'teo',      # EdgeOne
        'apigateway', # API 网关
        'vod',      # 视频点播
        'tke',      # 容器服务
        'tcb',      # CloudBase
        'tse',      # 微服务引擎
        'cos',      # 对象存储
        'scf',      # 云函数自定义域名
    ]

    def __init__(self, secret_id: str, secret_key: str, region: str = 'ap-guangzhou'):
        """
        初始化腾讯云 SSL 客户端

        Args:
            secret_id: 腾讯云 SecretId
            secret_key: 腾讯云 SecretKey
            region: 地域
        """
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile

        http_profile = HttpProfile()
        http_profile.endpoint = 'ssl.tencentcloudapi.com'

        client_profile = ClientProfile()
        client_profile.httpProfile = http_profile

        self.client = ssl_client.SslClient(
            credential=Credential(secret_id, secret_key),
            region=region,
            profile=client_profile
        )
        self.secret_id = secret_id
        self.secret_key = secret_key

    def upload_certificate(
        self,
        cert_pem: str,
        key_pem: str
    ) -> str:
        """
        上传证书到腾讯云 SSL 服务

        Args:
            cert_pem: 证书内容（PEM 格式）
            key_pem: 私钥内容（PEM 格式）

        Returns:
            证书 ID
        """
        req = ssl_models.UploadCertificateRequest()
        req.CertificatePublicKey = cert_pem
        req.CertificatePrivateKey = key_pem

        resp = self.client.UploadCertificate(req)
        return getattr(resp, 'CertificateId', '')

    def get_certificate_list(
        self,
        limit: int = 20,
        offset: int = 0,
        search_key: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        获取证书列表

        Args:
            limit: 返回数量
            offset: 偏移量
            search_key: 搜索关键词（域名或备注）

        Returns:
            证书列表
        """
        req = ssl_models.DescribeCertificatesRequest()
        req.Limit = limit
        req.Offset = offset
        if search_key:
            req.SearchKey = search_key

        resp = self.client.DescribeCertificates(req)
        # 将 SDK 对象转换为字典以便 JSON 序列化
        certificates = []
        if resp.Certificates:
            for cert in resp.Certificates:
                certificates.append({
                    'CertificateId': getattr(cert, 'CertificateId', ''),
                    'Domain': getattr(cert, 'Domain', ''),
                    'Alias': getattr(cert, 'Alias', ''),
                    'Status': getattr(cert, 'Status', ''),
                    'StatusName': getattr(cert, 'StatusName', ''),
                    'CertBeginTime': getattr(cert, 'CertBeginTime', ''),
                    'CertEndTime': getattr(cert, 'CertEndTime', ''),
                    'CommonName': getattr(cert, 'CommonName', ''),
                    'SubjectAltName': getattr(cert, 'SubjectAltName', ''),
                    'Issuer': getattr(cert, 'Issuer', ''),
                    'ProductZhName': getattr(cert, 'ProductZhName', ''),
                    'Deployable': getattr(cert, 'Deployable', False),
                    'BoundResource': getattr(cert, 'BoundResource', []),
                    'EncryptAlgorithm': getattr(cert, 'EncryptAlgorithm', ''),
                    'RenewAble': getattr(cert, 'RenewAble', False),
                    'IsVip': getattr(cert, 'IsVip', False),
                    'IsWildcard': getattr(cert, 'IsWildcard', False),
                    'IsDv': getattr(cert, 'IsDv', False),
                })
        return certificates

    def get_certificate_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        根据域名查询证书

        Args:
            domain: 域名

        Returns:
            证书信息，如果不存在返回 None
        """
        certs = self.get_certificate_list(limit=100, search_key=domain)

        for cert in certs:
            # 检查证书中的域名
            cert_domain = cert.get('Domain', '')
            if domain in cert_domain or cert_domain in domain:
                return {
                    'CertificateId': cert.get('CertificateId'),
                    'Domain': cert.get('Domain'),
                    'Alias': cert.get('Alias'),
                    'Status': cert.get('Status'),
                    'CertBeginTime': cert.get('CertBeginTime'),
                    'CertEndTime': cert.get('CertEndTime'),
                    'CommonName': cert.get('CommonName'),
                }

        return None

    def get_certificate_id(self, domain: str) -> Optional[str]:
        """
        根据域名获取证书 ID

        Args:
            domain: 域名

        Returns:
            证书 ID，如果不存在返回 None
        """
        cert = self.get_certificate_by_domain(domain)
        return cert['CertificateId'] if cert else None

    def delete_certificate(self, cert_id: str) -> bool:
        """
        删除证书

        Args:
            cert_id: 证书 ID

        Returns:
            是否成功
        """
        req = ssl_models.DeleteCertificateRequest()
        req.CertificateId = cert_id

        self.client.DeleteCertificate(req)
        return True

    def deploy_certificate(
        self,
        cert_id: str,
        resource_type: str,
        resource_ids: List[str],
        domain: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        部署证书到云资源

        Args:
            cert_id: 证书 ID
            resource_type: 资源类型 (cdn, clb, waf 等)
            resource_ids: 资源 ID 列表
            domain: 域名（某些资源类型需要）

        Returns:
            部署结果
        """
        req = ssl_models.DeployCertificateInstanceRequest()
        req.CertificateId = cert_id
        req.ResourceType = resource_type
        req.ResourceIds = resource_ids
        if domain:
            req.Domain = domain

        # 检查资源类型是否支持
        if resource_type not in self.RESOURCE_TYPES:
            raise ValueError(f'Unsupported resource type: {resource_type}')

        resp = self.client.DeployCertificateInstance(req)
        return {
            'DeploymentId': getattr(resp, 'DeploymentId', ''),
            'Status': getattr(resp, 'Status', ''),
        }

    def deploy_to_cdn(self, cert_id: str, domain: str) -> Dict[str, Any]:
        """
        部署证书到 CDN

        Args:
            cert_id: 证书 ID
            domain: 域名

        Returns:
            部署结果
        """
        return self.deploy_certificate(cert_id, 'cdn', [domain], domain)

    def deploy_to_clb(self, cert_id: str, listener_ids: List[str]) -> Dict[str, Any]:
        """
        部署证书到负载均衡

        Args:
            cert_id: 证书 ID
            listener_ids: 监听器 ID 列表

        Returns:
            部署结果
        """
        return self.deploy_certificate(cert_id, 'clb', listener_ids)

    def update_certificate(
        self,
        old_cert_id: str,
        cert_pem: str,
        key_pem: str,
        alias: str = ''
    ) -> str:
        """
        更新证书内容（保持证书 ID 不变）

        Args:
            old_cert_id: 原证书 ID
            cert_pem: 新证书内容
            key_pem: 新私钥内容
            alias: 新证书别名

        Returns:
            新证书 ID
        """
        req = ssl_models.UploadUpdateCertificateInstanceRequest()
        req.OldCertificateId = old_cert_id
        req.CertificatePublicKey = cert_pem
        req.CertificatePrivateKey = key_pem
        req.CertificateAlias = alias or 'acme-auto'

        resp = self.client.UploadUpdateCertificateInstance(req)
        return getattr(resp, 'CertificateId', '')

    def check_certificate_status(self, cert_id: str) -> Dict[str, Any]:
        """
        检查证书状态

        Args:
            cert_id: 证书 ID

        Returns:
            证书状态信息
        """
        req = ssl_models.DescribeCertificateDetailRequest()
        req.CertificateId = cert_id

        resp = self.client.DescribeCertificateDetail(req)
        cert = resp.CertificateDetail

        return {
            'CertificateId': getattr(cert, 'CertificateId', ''),
            'Domain': getattr(cert, 'Domain', ''),
            'Status': getattr(cert, 'Status', ''),
            'StatusMsg': getattr(cert, 'StatusMsg', ''),
            'CertBeginTime': getattr(cert, 'CertBeginTime', ''),
            'CertEndTime': getattr(cert, 'CertEndTime', ''),
            'CommonName': getattr(cert, 'CommonName', ''),
            'SubjectAltName': getattr(cert, 'SubjectAltName', []),
            'Issuer': getattr(cert, 'Issuer', ''),
            'ValidityPeriod': getattr(cert, 'ValidityPeriod', 0),
        }

    def replace_certificate(
        self,
        cert_id: str,
        resource_type: str,
        resource_ids: List[str]
    ) -> Dict[str, Any]:
        """
        替换资源的证书（一键替换）

        Args:
            cert_id: 新证书 ID
            resource_type: 资源类型
            resource_ids: 资源 ID 列表

        Returns:
            替换结果
        """
        req = ssl_models.UpdateCertificateInstanceRequest()
        req.CertificateId = cert_id
        req.ResourceType = resource_type
        req.ResourceIds = resource_ids

        resp = self.client.UpdateCertificateInstance(req)
        return {
            'Status': getattr(resp, 'Status', ''),
        }


class SCFCustomDomainHandler:
    """云函数自定义域名配置处理器"""

    def __init__(self, secret_id: str, secret_key: str, region: str = 'ap-guangzhou'):
        """
        初始化 SCF 自定义域名处理器

        Args:
            secret_id: 腾讯云 SecretId
            secret_key: 腾讯云 SecretKey
            region: 地域
        """
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        from tencentcloud.scf.v20180416 import scf_client, models as scf_models

        http_profile = HttpProfile()
        http_profile.endpoint = 'scf.tencentcloudapi.com'

        client_profile = ClientProfile()
        client_profile.httpProfile = http_profile

        self.client = scf_client.ScfClient(
            credential=Credential(secret_id, secret_key),
            region=region,
            profile=client_profile
        )
        self.region = region

    def update_domain_certificate(
        self,
        namespace: str,
        domain: str,
        cert_id: str
    ) -> bool:
        """
        更新 SCF 自定义域名的 HTTPS 证书

        Args:
            namespace: 命名空间
            domain: 自定义域名
            cert_id: 证书 ID

        Returns:
            是否成功
        """
        from tencentcloud.scf.v20180416 import models as scf_models

        req = scf_models.UpdateCustomDomainRequest()
        req.Namespace = namespace
        req.Domain = domain

        # 设置证书配置
        req.CustomDomain = scf_models.CustomDomain()
        req.CustomDomain.CertConfig = scf_models.CertConf()
        req.CustomDomain.CertConfig.CertId = cert_id

        self.client.UpdateCustomDomain(req)
        return True

    def get_custom_domain(self, namespace: str, domain: str) -> Dict[str, Any]:
        """
        获取自定义域名配置

        Args:
            namespace: 命名空间
            domain: 自定义域名

        Returns:
            域名配置信息
        """
        from tencentcloud.scf.v20180416 import models as scf_models

        req = scf_models.GetCustomDomainRequest()
        req.Namespace = namespace
        req.Domain = domain

        resp = self.client.GetCustomDomain(req)
        custom_domain = getattr(resp, 'CustomDomain', None)
        cert_config = getattr(custom_domain, 'CertConfig', None) if custom_domain else None

        return {
            'Domain': getattr(custom_domain, 'Domain', ''),
            'CertId': getattr(cert_config, 'CertId', None) if cert_config else None,
            'Protocol': getattr(custom_domain, 'Protocol', ''),
            'Status': getattr(custom_domain, 'Status', ''),
        }
