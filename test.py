"""
测试模块
用于本地测试证书申请功能
"""
import os
import sys
import json
from datetime import datetime

# 添加当前目录到 Python 路径
sys.path.insert(0, os.path.dirname(__file__))

from config import Config
from acme_handler import AcmeCertificateHandler
from dns_handler import DNSPodV3Handler
from tencent_ssl import TencentSSLHandler
from utils import CertificateUtils, DomainParser


def test_dns_handler():
    """测试 DNSPod API"""
    print('=' * 60)
    print('Testing DNSPod Handler')
    print('=' * 60)

    if not Config.TENCENT_SECRET_ID or not Config.TENCENT_SECRET_KEY:
        print('TENCENT_SECRET_ID and TENCENT_SECRET_KEY not configured')
        return False

    dns = DNSPodV3Handler(
        Config.TENCENT_SECRET_ID,
        Config.TENCENT_SECRET_KEY
    )

    # 测试域名
    test_domain = 'example.com'

    try:
        # 获取记录列表
        print(f'\nFetching DNS records for {test_domain}...')
        records = dns.get_dns_records(test_domain)
        print(f'Found {len(records)} records')

        for record in records[:5]:
            print(f'  - {record.get("Name", "N/A")} ({record.get("Type", "N/A")}): {record.get("Value", "N/A")}')

        print('\nDNSPod Handler test: PASSED')
        return True

    except Exception as e:
        print(f'\nDNSPod Handler test: FAILED - {e}')
        return False


def test_acme_handler():
    """测试 ACME 处理器"""
    print('\n' + '=' * 60)
    print('Testing ACME Handler')
    print('=' * 60)

    acme = AcmeCertificateHandler()

    # 检查 acme.sh 安装状态
    print(f'\nChecking acme.sh installation...')
    is_installed = acme.is_acme_sh_installed()
    print(f'acme.sh installed: {is_installed}')

    if not is_installed:
        print('\nInstalling acme.sh...')
        install_result = acme.install_acme_sh()
        print(f'Install result: {"SUCCESS" if install_result else "FAILED"}')

    # 列出现有证书
    print(f'\nListing existing certificates...')
    certs = acme.list_certificates()
    print(f'Found {len(certs)} certificates')

    for cert in certs:
        print(f'  - {cert.get("domain", "N/A")} (expires: {cert.get("renew_time", "N/A")})')

    print('\nACME Handler test: PASSED')
    return True


def test_tencent_ssl():
    """测试腾讯云 SSL API"""
    print('\n' + '=' * 60)
    print('Testing Tencent SSL Handler')
    print('=' * 60)

    if not Config.TENCENT_SECRET_ID or not Config.TENCENT_SECRET_KEY:
        print('TENCENT_SECRET_ID and TENCENT_SECRET_KEY not configured')
        return False

    ssl = TencentSSLHandler(
        Config.TENCENT_SECRET_ID,
        Config.TENCENT_SECRET_KEY,
        Config.TENCENT_REGION
    )

    try:
        # 获取证书列表
        print(f'\nFetching certificate list...')
        certs = ssl.get_certificate_list(limit=10)
        print(f'Found {len(certs)} certificates')

        for cert in certs[:5]:
            print(f'  - {cert.get("Domain", "N/A")} (ID: {cert.get("CertificateId", "N/A")})')

        print('\nTencent SSL Handler test: PASSED')
        return True

    except Exception as e:
        print(f'\nTencent SSL Handler test: FAILED - {e}')
        return False


def test_utils():
    """测试工具函数"""
    print('\n' + '=' * 60)
    print('Testing Utils')
    print('=' * 60)

    # 测试域名解析
    test_domains = [
        'example.com',
        'www.example.com',
        '*.example.com',
        'sub.www.example.com',
    ]

    print('\nTesting domain parser:')
    for domain in test_domains:
        parsed = DomainParser.parse_domain(domain)
        print(f'  {domain:25} -> main: {parsed["main_domain"]:20} sub: {parsed["sub_domain"]}')

    # 测试泛域名判断
    print('\nTesting wildcard detection:')
    for domain in ['example.com', '*.example.com', 'www.example.com']:
        is_wildcard = DomainParser.is_wildcard_domain(domain)
        print(f'  {domain:25} -> wildcard: {is_wildcard}')

    print('\nUtils test: PASSED')
    return True


def test_cert_validation():
    """测试证书验证"""
    print('\n' + '=' * 60)
    print('Testing Certificate Validation')
    print('=' * 60)

    # 示例证书（自签名测试证书）
    test_cert = """-----BEGIN CERTIFICATE-----
MIIDkzCCAnugAwIBAgIUC5l6XJwmQtZMLhPqF9Lv9gPEsF0wDQYJKoZIhvcNAQEL
BQAwWTELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlamluZzEQMA4GA1UEBwwHSGFp
RElhbjEUMBIGA1UECgwLVGVzdCBDb21wYW55MRIwEAYDVQQDDAlsb2NhbGhvc3Qw
HhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBZMQswCQYDVQQGEwJDTjEQ
MA4GA1UECBHQkJlaW5nMRAwDgYDVQQHEAdIYWlEaWFuMRQwEgYDVQQKEwtUZXN0
IENvbXBhbnkxEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALZ4m5x3sJvLBDfj+CBClMtNKhLK3HChWE8SJR8vN/6esXRY
HxXgYC5hP+5FJJdFJ8mj5GMPwIaEJnIaPxo1MvFPLkGjMx2UJKCMGhOPXMR7KL8h
8y3RGz5sC+RmFqEVKK5HJvgJHyxfJ1H3YMXNj7Vc7K1kMNMNHzDsSvQD8V0W5M8x
YlZKJmRkFqVWT9KbPgKZQvMQF7L8sQNw3MPQYh1yFZB6dJ8mBJ9h3VY6gMnLlSbV
YNS2E8u1Lfq6bqF8mXgHqHO1Fq5K0N4y0RmCkKO7gKJcxmLVm8Q9xL5R3HmPvDxY
nz7QQt7McKqCFL1FNFJ8m3V5qN3H8HLnRZNjPqJvCnCJsCAwEAAaNTMFEwHQYDVR0
lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAsGA1UdDwQEAwIBBjAdBgNVHQ4EFgQ
UyJJ7KxN9aJgPv3xT6C8Y1v3xqI8wDQYJKoZIhvcNAQELBQADggEBAGgZ8W9qDyhR
-----END CERTIFICATE-----"""

    test_key = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2eJucd7CbywQ3
4/gggpTLSoSytxwoVhPEiUfLzf+nrF0WB8V4GAuYT+tRSSXRSfJo+RjD8CGhCZyGj
8aNTLxTy5BozMdlCSgJhoT1zEeyyvIfMt0Rs+bAvkZhalFiiuRyb4CR8sXydR92DF
zY+1XOytZDDTDR8w7Er0A/FdFuTPMWJWSiZkZBalVk/Smw+CmULzEBey/LEDcNzD
0GHdchWQenSfJgSfYd1WOoDJy5Um1WDUthPLtS36uam6hfJl4B6hztRauStDeMtEZ
gpCju4CiXMZy1ZvEPcS+Udh5j7w8WJ8+0ELezHCqghS9RTRSfJt1eajdx/By50WTY
z6ibwpwibAgMBAAECggEBAKbzK8RBjHl3YNG6YVs3BqLQcmLLF+B4bXXV9pVrKKUC
5tPYhFaFLnLzQXjDQc5WQWwLNGsYQ8yKPjBZKBnYdHgQZOgRqRpK1EVPF0BjCVMWL
-----END PRIVATE KEY-----"""

    print('\nParsing certificate info...')
    try:
        cert_info = CertificateUtils.parse_cert_info(test_cert)
        print(f'  Common Name: {cert_info["common_name"]}')
        print(f'  SAN Names: {cert_info["san_names"]}')
        print(f'  Issuer: {cert_info["issuer"]}')
        print(f'  Valid From: {cert_info["not_before"]}')
        print(f'  Valid To: {cert_info["not_after"]}')
        print(f'  Remaining Days: {cert_info["remaining_days"]}')

        print('\nCertificate Validation test: PASSED')
        return True
    except Exception as e:
        print(f'\nCertificate Validation test: FAILED - {e}')
        return False


def run_all_tests():
    """运行所有测试"""
    print('\n' + '=' * 60)
    print('SSL Certificate Manager - Test Suite')
    print(f'Time: {datetime.now().isoformat()}')
    print('=' * 60)

    results = {
        'DNSPod Handler': test_dns_handler(),
        'ACME Handler': test_acme_handler(),
        'Tencent SSL': test_tencent_ssl(),
        'Utils': test_utils(),
        'Certificate Validation': test_cert_validation(),
    }

    print('\n' + '=' * 60)
    print('Test Results Summary')
    print('=' * 60)

    for test_name, result in results.items():
        status = 'PASSED' if result else 'FAILED'
        print(f'  {test_name:30} [{status}]')

    passed = sum(1 for r in results.values() if r)
    total = len(results)

    print(f'\nTotal: {passed}/{total} tests passed')

    return all(results.values())


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
