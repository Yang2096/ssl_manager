"""
DNSPod API 封装模块
提供 DNS 记录管理功能
"""
from typing import Optional, Dict, Any

# Tencent Cloud SDK for DNSPod API V3
from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.dnspod.v20210323 import dnspod_client as DnspodClient
from tencentcloud.dnspod.v20210323 import models


class DNSPodV3Handler:
    """
    DNSPod API V3 客户端 (使用官方 SDK)
    使用腾讯云官方 SDK 实现，无需手动签名
    """

    def __init__(self, secret_id: str, secret_key: str, region: str = 'ap-guangzhou'):
        """
        初始化 DNSPod V3 客户端

        Args:
            secret_id: 腾讯云 SecretId
            secret_key: 腾讯云 SecretKey
            region: 地域
        """
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.region = region
        self._client = None

    @property
    def client(self):
        """懒加载客户端实例"""
        if self._client is None:
            cred = credential.Credential(self.secret_id, self.secret_key)
            self._client = DnspodClient.DnspodClient(cred, self.region)
        return self._client

    def _record_to_dict(self, record) -> Dict[str, Any]:
        """
        将 SDK 返回的 Record 对象转换为字典，保持与旧版 API 兼容

        Args:
            record: SDK 返回的 Record 对象

        Returns:
            字典格式的记录信息
        """
        return {
            'id': getattr(record, 'RecordId', 0),
            'Id': getattr(record, 'RecordId', 0),  # 兼容旧格式
            'name': getattr(record, 'Name', ''),
            'Name': getattr(record, 'Name', ''),  # 兼容旧格式
            'type': getattr(record, 'Type', ''),
            'Type': getattr(record, 'Type', ''),  # 兼容旧格式
            'value': getattr(record, 'Value', ''),
            'Value': getattr(record, 'Value', ''),  # 兼容旧格式
            'ttl': getattr(record, 'TTL', 600),
            'TTL': getattr(record, 'TTL', 600),  # 兼容旧格式
            'status': getattr(record, 'Status', ''),
            'updated_on': getattr(record, 'UpdatedOn', ''),
        }

    def add_txt_record(self, domain: str, sub_domain: str, value: str, record_id: Optional[int] = None) -> int:
        """
        添加或更新 TXT 记录

        Args:
            domain: 主域名
            sub_domain: 子域名
            value: TXT 记录值
            record_id: 如果提供，则更新现有记录

        Returns:
            记录 ID
        """
        try:
            if record_id:
                # 更新现有记录
                req = models.ModifyRecordRequest()
                req.Domain = domain
                req.RecordId = record_id
                req.SubDomain = sub_domain
                req.Value = value
                req.RecordType = 'TXT'
                req.RecordLine = '默认'
                req.TTL = 600
                resp = self.client.ModifyRecord(req)
                return record_id
            else:
                # 创建新记录
                req = models.CreateRecordRequest()
                req.Domain = domain
                req.SubDomain = sub_domain
                req.Value = value
                req.RecordType = 'TXT'
                req.RecordLine = '默认'
                req.TTL = 600
                resp = self.client.CreateRecord(req)
                return getattr(resp, 'RecordId', 0)
        except TencentCloudSDKException as e:
            raise Exception(f"DNSPod API Error: {e.get_message()}")

    def delete_dns_record(self, domain: str, record_id: int) -> bool:
        """
        删除 DNS 记录

        Args:
            domain: 主域名
            record_id: 记录 ID

        Returns:
            是否成功
        """
        try:
            req = models.DeleteRecordRequest()
            req.Domain = domain
            req.RecordId = record_id
            self.client.DeleteRecord(req)
            return True
        except TencentCloudSDKException as e:
            raise Exception(f"DNSPod API Error: {e.get_message()}")

    def get_dns_records(self, domain: str, subdomain: str = '') -> list:
        """
        获取 DNS 记录列表

        Args:
            domain: 主域名
            subdomain: 子域名过滤（可选）

        Returns:
            记录列表（字典格式，与旧版 API 兼容）
        """
        try:
            req = models.DescribeRecordListRequest()
            req.Domain = domain
            if subdomain:
                req.Subdomain = subdomain
            resp = self.client.DescribeRecordList(req)

            # 将 SDK 返回的 Record 列表转换为字典列表
            return [self._record_to_dict(record) for record in resp.RecordList]
        except TencentCloudSDKException as e:
            # 当使用子域名过滤且没有匹配记录时，API 返回 ResourceNotFound.NoDataOfRecord
            # 这种情况下返回空列表而不是抛出异常
            if e.code == 'ResourceNotFound.NoDataOfRecord':
                return []
            raise Exception(f"DNSPod API Error: {e.get_message()}")
