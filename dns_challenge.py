"""
DNS Challenge Coordinator
整合 DNSPodV3Handler 用于 ACME DNS-01 挑战
"""
import logging
import time
from typing import Callable, Optional, Dict, Any, List, Tuple

from dns_handler import DNSPodV3Handler
from utils import DomainParser

logger = logging.getLogger(__name__)


class DNSRecord:
    """DNS 记录信息"""

    def __init__(
        self,
        record_name: str,
        record_value: str,
        domain: str,
        sub_domain: str,
        record_id: Optional[int] = None
    ):
        self.record_name = record_name
        self.record_value = record_value
        self.domain = domain
        self.sub_domain = sub_domain
        self.record_id = record_id

    def __repr__(self):
        return f'DNSRecord({self.record_name}={self.record_value}, id={self.record_id})'


class DNSChallengeHandler:
    """
    DNS 挑战协调器
    整合 DNSPodV3Handler 用于 ACME DNS-01 挑战
    """

    def __init__(self, secret_id: str, secret_key: str, region: str = 'ap-guangzhou'):
        """
        初始化 DNS 挑战处理器

        Args:
            secret_id: 腾讯云 SecretId
            secret_key: 腾讯云 SecretKey
            region: 地域
        """
        self.dns_handler = DNSPodV3Handler(secret_id, secret_key, region)
        self._added_records: List[DNSRecord] = []

    def _extract_main_domain(self, full_domain: str) -> Tuple[str, str]:
        """
        提取主域名和子域名

        Args:
            full_domain: 完整域名，如 _acme-challenge.sub.example.com

        Returns:
            (主域名, 子域名) 元组
        """
        # 移除 _acme-challenge 前缀（如果存在）
        if full_domain.startswith('_acme-challenge.'):
            domain_part = full_domain[len('_acme-challenge.'):]
        else:
            domain_part = full_domain

        # 使用 DomainParser 解析
        parsed = DomainParser.parse_domain(domain_part)
        main_domain = parsed['main_domain']

        # 计算子域名部分
        if domain_part == main_domain:
            sub_domain = '@'
        else:
            # 从 domain_part 中移除 main_domain 得到子域名
            sub_domain = domain_part[:-len(main_domain)].rstrip('.')

            # 如果子域名以 _acme-challenge 开头，保持完整
            if full_domain.startswith('_acme-challenge.'):
                if sub_domain == '@':
                    sub_domain = '_acme-challenge'
                else:
                    sub_domain = f'_acme-challenge.{sub_domain}'

        return main_domain, sub_domain

    def add_validation_record(
        self,
        record_name: str,
        record_value: str,
        ttl: int = 600
    ) -> DNSRecord:
        """
        添加 DNS 验证记录

        Args:
            record_name: 记录名称，如 _acme-challenge.example.com
            record_value: 记录值
            ttl: TTL 时间

        Returns:
            DNS 记录对象
        """
        logger.info(f'Adding DNS validation record: {record_name} = {record_value}')

        # 解析域名
        main_domain, sub_domain = self._extract_main_domain(record_name)

        logger.info(f'Parsed: main_domain={main_domain}, sub_domain={sub_domain}')

        # 检查是否已存在相同记录
        existing_records = self.dns_handler.get_dns_records(main_domain, sub_domain.split('.')[-1] if sub_domain != '@' else '')
        for record in existing_records:
            if record.get('Value') == record_value and record.get('Type') == 'TXT':
                logger.info(f'DNS record already exists: {record.get("Id")}')
                dns_record = DNSRecord(
                    record_name=record_name,
                    record_value=record_value,
                    domain=main_domain,
                    sub_domain=sub_domain,
                    record_id=record.get('Id')
                )
                self._added_records.append(dns_record)
                return dns_record

        # 添加新记录
        record_id = self.dns_handler.add_txt_record(
            domain=main_domain,
            sub_domain=sub_domain,
            value=record_value
        )

        dns_record = DNSRecord(
            record_name=record_name,
            record_value=record_value,
            domain=main_domain,
            sub_domain=sub_domain,
            record_id=record_id
        )

        self._added_records.append(dns_record)
        logger.info(f'DNS record added with ID: {record_id}')

        return dns_record

    def cleanup_record(self, record: DNSRecord) -> bool:
        """
        清理单个 DNS 记录

        Args:
            record: DNS 记录对象

        Returns:
            是否成功
        """
        if record.record_id is None:
            logger.warning(f'Cannot cleanup record without ID: {record.record_name}')
            return False

        try:
            logger.info(f'Deleting DNS record: {record.record_name} (ID: {record.record_id})')
            self.dns_handler.delete_dns_record(record.domain, record.record_id)
            return True
        except Exception as e:
            logger.error(f'Failed to delete DNS record {record.record_name}: {e}')
            return False

    def cleanup_records(self) -> Dict[str, Any]:
        """
        清理所有添加的 DNS 记录

        Returns:
            清理结果
        """
        results = {
            'total': len(self._added_records),
            'success': 0,
            'failed': 0,
            'records': []
        }

        for record in self._added_records:
            if self.cleanup_record(record):
                results['success'] += 1
                results['records'].append({
                    'name': record.record_name,
                    'status': 'deleted'
                })
            else:
                results['failed'] += 1
                results['records'].append({
                    'name': record.record_name,
                    'status': 'failed'
                })

        # 清空记录列表
        self._added_records.clear()

        return results

    def verify_dns_propagation(
        self,
        record_name: str,
        record_value: str,
        timeout: int = 120,
        check_interval: int = 5
    ) -> bool:
        """
        验证 DNS 记录是否已传播

        Args:
            record_name: 记录名称
            record_value: 期望的记录值
            timeout: 超时时间（秒）
            check_interval: 检查间隔（秒）

        Returns:
            是否已传播
        """
        logger.info(f'Verifying DNS propagation for {record_name}')

        main_domain, sub_domain = self._extract_main_domain(record_name)

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                records = self.dns_handler.get_dns_records(main_domain)
                for record in records:
                    if record.get('Value') == record_value:
                        logger.info(f'DNS record propagated successfully')
                        return True
            except Exception as e:
                logger.debug(f'DNS check failed: {e}')

            logger.debug(f'DNS not yet propagated, waiting {check_interval}s...')
            time.sleep(check_interval)

        logger.warning(f'DNS propagation timeout for {record_name}')
        return False

    def get_record_by_name(self, record_name: str) -> Optional[DNSRecord]:
        """
        根据记录名获取已添加的记录

        Args:
            record_name: 记录名称

        Returns:
            DNS 记录对象，如果不存在返回 None
        """
        for record in self._added_records:
            if record.record_name == record_name:
                return record
        return None

    def get_added_records(self) -> List[DNSRecord]:
        """
        获取所有已添加的记录

        Returns:
            DNS 记录列表
        """
        return self._added_records.copy()


class DNSChallengeCallback:
    """
    DNS 挑战回调适配器
    将 DNSChallengeHandler 适配为 PureACMEClient 需要的回调函数
    """

    def __init__(self, handler: DNSChallengeHandler):
        """
        初始化回调适配器

        Args:
            handler: DNS 挑战处理器
        """
        self.handler = handler

    def add_record(self, record_name: str, record_value: str) -> bool:
        """
        添加 DNS 记录回调

        Args:
            record_name: 记录名称
            record_value: 记录值

        Returns:
            是否成功
        """
        try:
            self.handler.add_validation_record(record_name, record_value)
            return True
        except Exception as e:
            logger.error(f'Failed to add DNS record: {e}')
            return False

    def cleanup_record(self, record_name: str, record_value: str) -> bool:
        """
        清理 DNS 记录回调

        Args:
            record_name: 记录名称
            record_value: 记录值

        Returns:
            是否成功
        """
        record = self.handler.get_record_by_name(record_name)
        if record:
            return self.handler.cleanup_record(record)
        return False

    def cleanup_all(self) -> Dict[str, Any]:
        """
        清理所有记录

        Returns:
            清理结果
        """
        return self.handler.cleanup_records()


def create_dns_challenge_handler(
    secret_id: str,
    secret_key: str,
    region: str = 'ap-guangzhou'
) -> DNSChallengeCallback:
    """
    创建 DNS 挑战回调处理器

    Args:
        secret_id: 腾讯云 SecretId
        secret_key: 腾讯云 SecretKey
        region: 地域

    Returns:
        DNS 挑战回调处理器
    """
    handler = DNSChallengeHandler(secret_id, secret_key, region)
    return DNSChallengeCallback(handler)
