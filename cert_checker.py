"""
Certificate Expiry Checker
检查证书过期时间并触发自动续期
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from tencent_ssl import TencentSSLHandler

logger = logging.getLogger(__name__)


class CertificateExpiryChecker:
    """
    证书过期检查器
    检查腾讯云 SSL 证书列表中的即将过期证书
    """

    def __init__(self, ssl_handler: TencentSSLHandler):
        """
        初始化证书过期检查器

        Args:
            ssl_handler: 腾讯云 SSL 处理器
        """
        self.ssl_handler = ssl_handler

    def _parse_end_time(self, end_time: str) -> Optional[datetime]:
        """
        解析过期时间字符串

        Args:
            end_time: 过期时间字符串，格式如 '2024-12-31 23:59:59'

        Returns:
            datetime 对象，解析失败返回 None
        """
        try:
            # 尝试多种时间格式
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S.%fZ',
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(end_time, fmt)
                except ValueError:
                    continue
            return None
        except Exception:
            return None

    def _calculate_remaining_days(self, end_time: str) -> Optional[int]:
        """
        计算剩余天数

        Args:
            end_time: 过期时间字符串

        Returns:
            剩余天数，解析失败返回 None
        """
        dt = self._parse_end_time(end_time)
        if dt is None:
            return None

        # 处理时区差异（腾讯云返回的时间可能是本地时区）
        now = datetime.now()
        delta = dt - now
        return delta.days

    def check_certificates_expiring(
        self,
        days_threshold: int = 30
    ) -> List[Dict[str, Any]]:
        """
        检查即将过期的证书

        Args:
            days_threshold: 过期阈值（天），默认 30 天

        Returns:
            即将过期的证书列表
        """
        logger.info(f'Checking certificates expiring within {days_threshold} days')

        certs = self.ssl_handler.get_certificate_list(limit=100)
        expiring = []

        for cert in certs:
            end_time = cert.get('CertEndTime') or cert.get('endTime')
            if not end_time:
                continue

            remaining_days = self._calculate_remaining_days(end_time)
            if remaining_days is None:
                continue

            if remaining_days <= days_threshold:
                expiring.append({
                    'certificate_id': cert.get('CertificateId'),
                    'domain': cert.get('Domain'),
                    'alias': cert.get('Alias'),
                    'remaining_days': remaining_days,
                    'end_time': end_time,
                    'status': cert.get('Status'),
                })
                logger.info(
                    f'Certificate {cert.get("Domain")} expires in {remaining_days} days'
                )

        logger.info(f'Found {len(expiring)} expiring certificates')
        return expiring

    def check_domain_certificate(
        self,
        domain: str,
        days_threshold: int = 30
    ) -> Optional[Dict[str, Any]]:
        """
        检查特定域名的证书是否即将过期

        Args:
            domain: 域名
            days_threshold: 过期阈值（天）

        Returns:
            证书信息，如果不存在或未过期返回 None
        """
        cert = self.ssl_handler.get_certificate_by_domain(domain)
        if not cert:
            return None

        end_time = cert.get('CertEndTime') or cert.get('endTime')
        if not end_time:
            return None

        remaining_days = self._calculate_remaining_days(end_time)
        if remaining_days is None:
            return None

        return {
            'certificate_id': cert.get('CertificateId'),
            'domain': cert.get('Domain'),
            'remaining_days': remaining_days,
            'end_time': end_time,
            'is_expiring': remaining_days <= days_threshold,
            'is_expired': remaining_days <= 0,
        }

    def get_renewal_candidates(
        self,
        days_threshold: int = 30
    ) -> List[Dict[str, Any]]:
        """
        获取需要续期的证书列表

        Args:
            days_threshold: 过期阈值（天）

        Returns:
            需要续期的证书列表
        """
        expiring = self.check_certificates_expiring(days_threshold)
        return [
            cert for cert in expiring
            if cert['status'] not in ('revoked', 'expired', 'revoking')
        ]

    def check_all_certificates(self) -> Dict[str, Any]:
        """
        检查所有证书的状态

        Returns:
            证书状态汇总
        """
        certs = self.ssl_handler.get_certificate_list(limit=100)

        summary = {
            'total': len(certs),
            'valid': 0,
            'expiring_soon': 0,  # 30天内过期
            'expiring_very_soon': 0,  # 7天内过期
            'expired': 0,
            'certificates': []
        }

        for cert in certs:
            end_time = cert.get('CertEndTime') or cert.get('endTime')
            if not end_time:
                continue

            remaining_days = self._calculate_remaining_days(end_time)
            if remaining_days is None:
                continue

            cert_info = {
                'certificate_id': cert.get('CertificateId'),
                'domain': cert.get('Domain'),
                'remaining_days': remaining_days,
                'end_time': end_time,
                'status': cert.get('Status'),
            }

            if remaining_days <= 0:
                summary['expired'] += 1
                cert_info['urgency'] = 'expired'
            elif remaining_days <= 7:
                summary['expiring_very_soon'] += 1
                summary['expiring_soon'] += 1
                cert_info['urgency'] = 'critical'
            elif remaining_days <= 30:
                summary['expiring_soon'] += 1
                cert_info['urgency'] = 'warning'
            else:
                summary['valid'] += 1
                cert_info['urgency'] = 'ok'

            summary['certificates'].append(cert_info)

        return summary


class RenewalPlan:
    """
    续期计划生成器
    根据证书状态生成续期计划
    """

    def __init__(self, checker: CertificateExpiryChecker):
        """
        初始化续期计划生成器

        Args:
            checker: 证书过期检查器
        """
        self.checker = checker

    def generate_renewal_plan(
        self,
        days_threshold: int = 30,
        batch_size: int = 10
    ) -> Dict[str, Any]:
        """
        生成续期计划

        Args:
            days_threshold: 过期阈值（天）
            batch_size: 批次大小

        Returns:
            续期计划
        """
        candidates = self.checker.get_renewal_candidates(days_threshold)

        # 按剩余天数排序
        candidates.sort(key=lambda x: x['remaining_days'])

        # 分批
        batches = []
        for i in range(0, len(candidates), batch_size):
            batches.append(candidates[i:i + batch_size])

        return {
            'total': len(candidates),
            'batch_size': batch_size,
            'batch_count': len(batches),
            'batches': batches,
        }

    def get_priority_list(self, days_threshold: int = 30) -> List[Dict[str, Any]]:
        """
        获取优先续期列表

        Args:
            days_threshold: 过期阈值（天）

        Returns:
            按优先级排序的证书列表
        """
        candidates = self.checker.get_renewal_candidates(days_threshold)

        # 计算优先级分数（剩余天数越少，优先级越高）
        for cert in candidates:
            remaining_days = cert['remaining_days']
            if remaining_days <= 0:
                cert['priority'] = 100
            elif remaining_days <= 7:
                cert['priority'] = 90 + (7 - remaining_days)
            elif remaining_days <= 30:
                cert['priority'] = 50 + (30 - remaining_days) // 2
            else:
                cert['priority'] = 10

        # 按优先级排序
        candidates.sort(key=lambda x: x['priority'], reverse=True)

        return candidates


class AutoRenewalOrchestrator:
    """
    自动续期协调器
    整合证书检查和续期流程
    """

    def __init__(
        self,
        ssl_handler: TencentSSLHandler,
        acme_client_class,
        dns_challenge_callback,
        days_threshold: int = 30
    ):
        """
        初始化自动续期协调器

        Args:
            ssl_handler: 腾讯云 SSL 处理器
            acme_client_class: ACME 客户端类
            dns_challenge_callback: DNS 挑战回调
            days_threshold: 过期阈值（天）
        """
        self.ssl_handler = ssl_handler
        self.acme_client_class = acme_client_class
        self.dns_challenge_callback = dns_challenge_callback
        self.days_threshold = days_threshold
        self.checker = CertificateExpiryChecker(ssl_handler)

    def check_and_renew(
        self,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        检查并续期即将过期的证书

        Args:
            dry_run: 是否只检查不执行续期

        Returns:
            执行结果
        """
        logger.info('Starting automatic certificate renewal check')

        # 获取需要续期的证书
        candidates = self.checker.get_renewal_candidates(self.days_threshold)

        results = {
            'checked': len(candidates),
            'renewed': 0,
            'failed': 0,
            'skipped': 0,
            'details': []
        }

        for cert in candidates:
            domain = cert['domain']
            cert_id = cert['certificate_id']
            remaining_days = cert['remaining_days']

            logger.info(f'Processing certificate for {domain} ({remaining_days} days remaining)')

            if dry_run:
                results['skipped'] += 1
                results['details'].append({
                    'domain': domain,
                    'action': 'skipped',
                    'reason': 'dry_run'
                })
                continue

            try:
                # 创建 ACME 客户端
                acme_client = self.acme_client_class()

                # 申请证书
                issue_result = acme_client.request_certificate(
                    domains=[domain],
                    dns_record_callback=self.dns_challenge_callback.add_record,
                    dns_cleanup_callback=self.dns_challenge_callback.cleanup_record
                )

                if issue_result.get('success'):
                    # 更新腾讯云证书
                    new_cert_id = self.ssl_handler.update_certificate(
                        old_cert_id=cert_id,
                        cert_pem=issue_result['cert_pem'],
                        key_pem=issue_result['key_pem'],
                        alias=f'{domain}-acme'
                    )

                    results['renewed'] += 1
                    results['details'].append({
                        'domain': domain,
                        'action': 'renewed',
                        'old_cert_id': cert_id,
                        'new_cert_id': new_cert_id
                    })

                    logger.info(f'Successfully renewed certificate for {domain}')
                else:
                    results['failed'] += 1
                    results['details'].append({
                        'domain': domain,
                        'action': 'failed',
                        'reason': issue_result.get('message')
                    })
                    logger.error(f'Failed to renew certificate for {domain}: {issue_result.get("message")}')

            except Exception as e:
                results['failed'] += 1
                results['details'].append({
                    'domain': domain,
                    'action': 'failed',
                    'reason': str(e)
                })
                logger.error(f'Error renewing certificate for {domain}: {e}')

        logger.info(
            f'Automatic renewal check completed: '
            f'{results["renewed"]} renewed, {results["failed"]} failed, {results["skipped"]} skipped'
        )

        return results
