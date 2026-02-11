"""
云函数入口
腾讯云 SCF 云函数入口文件
"""
import json
import logging
import os
import sys
import traceback
from typing import Any, Dict, Optional

# 尝试加载 .env 文件（本地开发时使用）
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from config import Config
from acme_handler import AcmeCertificateHandler
from tencent_ssl import TencentSSLHandler, SCFCustomDomainHandler

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Response:
    """云函数响应类"""

    @staticmethod
    def success(data: Any, message: str = 'Success') -> Dict[str, Any]:
        """成功响应"""
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': True,
                'message': message,
                'data': data,
            }, ensure_ascii=False)
        }

    @staticmethod
    def error(message: str, code: int = 500, data: Any = None) -> Dict[str, Any]:
        """错误响应"""
        return {
            'statusCode': code,
            'body': json.dumps({
                'success': False,
                'message': message,
                'data': data,
            }, ensure_ascii=False)
        }


def validate_config() -> tuple[bool, Optional[Dict[str, Any]]]:
    """
    验证配置

    Returns:
        (是否有效, 错误响应)
    """
    is_valid, errors = Config.validate()
    if not is_valid:
        return False, Response.error(
            'Configuration validation failed',
            400,
            {'errors': errors}
        )
    return True, None


def issue_new_certificate(domain: str, staging: bool = False) -> Dict[str, Any]:
    """
    申请新证书并上传到腾讯云

    Args:
        domain: 域名
        staging: 是否使用测试环境

    Returns:
        响应结果
    """
    try:
        logger.info(f'Starting certificate issuance for {domain}')

        # 验证配置
        is_valid, error_response = validate_config()
        if not is_valid:
            return error_response

        # 初始化处理器
        acme = AcmeCertificateHandler()
        ssl_handler = TencentSSLHandler(
            Config.TENCENT_SECRET_ID,
            Config.TENCENT_SECRET_KEY,
            Config.TENCENT_REGION
        )

        # 1. 检查是否已有证书
        existing_cert = ssl_handler.get_certificate_by_domain(domain)
        if existing_cert:
            logger.info(f'Certificate already exists for {domain}: {existing_cert["CertificateId"]}')
            return Response.success(
                existing_cert,
                f'Certificate already exists for {domain}'
            )

        # 2. 申请证书
        issue_result = acme.issue_certificate(domain, staging)
        if not issue_result.get('success'):
            return Response.error(
                issue_result.get('message', 'Certificate issuance failed'),
                500
            )

        # 3. 获取证书内容
        cert_pem, key_pem = acme.get_certificate(domain)
        if not cert_pem or not key_pem:
            return Response.error(
                'Failed to read certificate files',
                500
            )

        # 4. 上传到腾讯云
        cert_id = ssl_handler.upload_certificate(
            cert_pem,
            key_pem
        )

        logger.info(f'Certificate uploaded successfully: {cert_id}')

        # 5. 返回结果
        return Response.success({
            'domain': domain,
            'certificateId': cert_id,
            'staging': staging,
            'message': 'Certificate issued and uploaded successfully',
        }, 'Certificate issued successfully')

    except Exception as e:
        logger.error(f'Error in issue_new_certificate: {e}')
        logger.error(traceback.format_exc())
        return Response.error(
            f'Internal server error: {str(e)}',
            500
        )


def issue_certificate_local(
    domain: str,
    email: Optional[str] = None,
    staging: Optional[bool] = None,
    work_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    本地申请证书（不上传到腾讯云）

    Args:
        domain: 域名
        email: ACME 账户邮箱（可选，默认使用环境变量或默认值）
        staging: 是否使用测试环境（可选，默认使用环境变量或默认值）
        work_dir: 工作目录（可选，默认使用 ./certs）

    Returns:
        响应结果
    """
    try:
        logger.info(f'Starting local certificate issuance for {domain}')

        # 设置工作目录（默认为项目目录下的 ./certs）
        if work_dir is None:
            work_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs')

        # 确保工作目录存在
        os.makedirs(work_dir, exist_ok=True)

        # 设置邮箱
        if email:
            os.environ['ACME_ACCOUNT_EMAIL'] = email

        # 确定 staging 参数
        if staging is None:
            staging = Config.ACME_STAGING

        # 验证 DNS 凭据
        if not Config.TENCENT_SECRET_ID or not Config.TENCENT_SECRET_KEY:
            return Response.error(
                'TENCENT_SECRET_ID and TENCENT_SECRET_KEY are required for DNS validation',
                400
            )

        # 初始化处理器
        acme = AcmeCertificateHandler(work_dir=work_dir)

        # 申请证书
        issue_result = acme.issue_certificate(domain, staging=staging)
        if not issue_result.get('success'):
            return Response.error(
                issue_result.get('message', 'Certificate issuance failed'),
                500
            )

        # 获取证书路径
        cert_path = issue_result.get('cert_path')
        key_path = issue_result.get('key_path')

        # 检查证书有效期
        expiry_info = acme.check_certificate_expiry(domain)

        result_data = {
            'domain': domain,
            'cert_path': cert_path,
            'key_path': key_path,
            'staging': staging,
            'message': 'Certificate issued successfully (local only)',
        }

        if expiry_info:
            result_data['expiry_date'] = expiry_info['expiry_date']
            result_data['remaining_days'] = expiry_info['remaining_days']

        logger.info(f'Certificate issued successfully: {cert_path}')

        return Response.success(result_data, 'Certificate issued successfully')

    except Exception as e:
        logger.error(f'Error in issue_certificate_local: {e}')
        logger.error(traceback.format_exc())
        return Response.error(
            f'Internal server error: {str(e)}',
            500
        )


def upload_existing_certificate(domain: str, cert_dir: str = None) -> Dict[str, Any]:
    """
    直接上传已申请的证书到腾讯云

    Args:
        domain: 域名
        cert_dir: 证书目录（默认为 ./certs/{domain}）

    Returns:
        响应结果
    """
    try:
        logger.info(f'Uploading existing certificate for {domain}')

        # 确定证书目录
        if cert_dir is None:
            cert_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs', domain)

        # 读取证书文件
        cert_path = os.path.join(cert_dir, 'fullchain.pem')
        key_path = os.path.join(cert_dir, 'privkey.pem')

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            return Response.error(
                f'Certificate files not found in {cert_dir}',
                404
            )

        with open(cert_path, 'r') as f:
            cert_pem = f.read()
        with open(key_path, 'r') as f:
            key_pem = f.read()

        # 验证配置
        is_valid, error_response = validate_config()
        if not is_valid:
            return error_response

        # 初始化 SSL 处理器
        ssl_handler = TencentSSLHandler(
            Config.TENCENT_SECRET_ID,
            Config.TENCENT_SECRET_KEY,
            Config.TENCENT_REGION
        )

        # 上传到腾讯云
        cert_id = ssl_handler.upload_certificate(cert_pem, key_pem)

        logger.info(f'Certificate uploaded successfully: {cert_id}')

        return Response.success({
            'domain': domain,
            'certificateId': cert_id,
            'message': 'Certificate uploaded successfully',
        }, 'Certificate uploaded successfully')

    except Exception as e:
        logger.error(f'Error in upload_existing_certificate: {e}')
        logger.error(traceback.format_exc())
        return Response.error(
            f'Internal server error: {str(e)}',
            500
        )


def renew_certificate(domain: str, force: bool = False) -> Dict[str, Any]:
    """
    续期证书

    Args:
        domain: 域名
        force: 是否强制续期

    Returns:
        响应结果
    """
    try:
        logger.info(f'Starting certificate renewal for {domain}')

        # 验证配置
        is_valid, error_response = validate_config()
        if not is_valid:
            return error_response

        # 初始化处理器
        acme = AcmeCertificateHandler()
        ssl_handler = TencentSSLHandler(
            Config.TENCENT_SECRET_ID,
            Config.TENCENT_SECRET_KEY,
            Config.TENCENT_REGION
        )

        # 1. 检查证书有效期
        expiry_info = acme.check_certificate_expiry(domain)
        if expiry_info and not expiry_info['is_expiring_soon'] and not force:
            logger.info(f'Certificate for {domain} is still valid')
            return Response.success(
                expiry_info,
                f'Certificate is still valid, expires in {expiry_info["remaining_days"]} days'
            )

        # 2. 续期证书
        renew_result = acme.renew_certificate(domain, force)
        if not renew_result.get('success'):
            return Response.error(
                renew_result.get('message', 'Certificate renewal failed'),
                500
            )

        # 3. 获取新证书内容
        cert_pem, key_pem = acme.get_certificate(domain)
        if not cert_pem or not key_pem:
            return Response.error(
                'Failed to read renewed certificate files',
                500
            )

        # 4. 查找现有证书 ID
        existing_cert = ssl_handler.get_certificate_by_domain(domain)
        if existing_cert:
            # 更新现有证书
            new_cert_id = ssl_handler.update_certificate(
                existing_cert['CertificateId'],
                cert_pem,
                key_pem,
                alias=f'{domain}-acme'
            )
            logger.info(f'Certificate updated: {new_cert_id}')
        else:
            # 上传新证书
            new_cert_id = ssl_handler.upload_certificate(
                cert_pem,
                key_pem
            )
            logger.info(f'Certificate uploaded: {new_cert_id}')

        return Response.success({
            'domain': domain,
            'certificateId': new_cert_id,
            'message': 'Certificate renewed successfully',
        }, 'Certificate renewed successfully')

    except Exception as e:
        logger.error(f'Error in renew_certificate: {e}')
        logger.error(traceback.format_exc())
        return Response.error(
            f'Internal server error: {str(e)}',
            500
        )


def deploy_certificate(
    domain: str,
    resource_type: str,
    resource_ids: list
) -> Dict[str, Any]:
    """
    部署证书到云资源

    Args:
        domain: 域名
        resource_type: 资源类型 (cdn, clb, waf 等)
        resource_ids: 资源 ID 列表

    Returns:
        响应结果
    """
    try:
        logger.info(f'Deploying certificate for {domain} to {resource_type}')

        # 验证配置
        is_valid, error_response = validate_config()
        if not is_valid:
            return error_response

        # 初始化 SSL 处理器
        ssl_handler = TencentSSLHandler(
            Config.TENCENT_SECRET_ID,
            Config.TENCENT_SECRET_KEY,
            Config.TENCENT_REGION
        )

        # 获取证书 ID
        cert_id = ssl_handler.get_certificate_id(domain)
        if not cert_id:
            return Response.error(
                f'Certificate not found for {domain}',
                404
            )

        # 部署证书
        deploy_result = ssl_handler.deploy_certificate(
            cert_id,
            resource_type,
            resource_ids
        )

        return Response.success({
            'domain': domain,
            'certificateId': cert_id,
            'resourceType': resource_type,
            'resourceIds': resource_ids,
            'deploymentId': deploy_result.get('DeploymentId'),
        }, 'Certificate deployed successfully')

    except Exception as e:
        logger.error(f'Error in deploy_certificate: {e}')
        logger.error(traceback.format_exc())
        return Response.error(
            f'Internal server error: {str(e)}',
            500
        )


def list_certificates(domain: Optional[str] = None) -> Dict[str, Any]:
    """
    列出证书

    Args:
        domain: 域名过滤（可选）

    Returns:
        响应结果
    """
    try:
        logger.info('Listing certificates')

        # 验证配置
        is_valid, error_response = validate_config()
        if not is_valid:
            return error_response

        # 初始化 SSL 处理器
        ssl_handler = TencentSSLHandler(
            Config.TENCENT_SECRET_ID,
            Config.TENCENT_SECRET_KEY,
            Config.TENCENT_REGION
        )

        # 获取证书列表
        certs = ssl_handler.get_certificate_list(limit=100, search_key=domain)

        # 列出 acme.sh 证书
        acme = AcmeCertificateHandler()
        acme_certs = acme.list_certificates()

        return Response.success({
            'tencent_ssl': certs,
            'acme_sh': acme_certs,
        }, 'Certificates listed successfully')

    except Exception as e:
        logger.error(f'Error in list_certificates: {e}')
        logger.error(traceback.format_exc())
        return Response.error(
            f'Internal server error: {str(e)}',
            500
        )


def check_and_renew() -> Dict[str, Any]:
    """
    检查并续期即将过期的证书（定时任务）

    Returns:
        响应结果
    """
    try:
        logger.info('Checking certificates for renewal')

        # 验证配置
        is_valid, error_response = validate_config()
        if not is_valid:
            return error_response

        # 初始化处理器
        acme = AcmeCertificateHandler()
        ssl_handler = TencentSSLHandler(
            Config.TENCENT_SECRET_ID,
            Config.TENCENT_SECRET_KEY,
            Config.TENCENT_REGION
        )

        # 获取所有证书
        certs = ssl_handler.get_certificate_list(limit=100)
        renewed = []

        for cert in certs:
            domain = cert.get('Domain', '')
            cert_id = cert.get('CertificateId', '')

            if not domain or not cert_id:
                continue

            # 检查有效期
            expiry_info = acme.check_certificate_expiry(domain)
            if expiry_info and expiry_info['is_expiring_soon']:
                logger.info(f'Renewing certificate for {domain}')

                # 续期证书
                renew_result = acme.renew_certificate(domain, force=False)
                if renew_result.get('success'):
                    # 获取新证书内容
                    cert_pem, key_pem = acme.get_certificate(domain)
                    if cert_pem and key_pem:
                        # 更新证书
                        ssl_handler.update_certificate(
                            cert_id,
                            cert_pem,
                            key_pem,
                            alias=f'{domain}-acme'
                        )
                        renewed.append({
                            'domain': domain,
                            'certificateId': cert_id,
                        })

        return Response.success({
            'checked': len(certs),
            'renewed': len(renewed),
            'certificates': renewed,
        }, f'Checked {len(certs)} certificates, renewed {len(renewed)}')

    except Exception as e:
        logger.error(f'Error in check_and_renew: {e}')
        logger.error(traceback.format_exc())
        return Response.error(
            f'Internal server error: {str(e)}',
            500
        )


def main_handler(event, context) -> Dict[str, Any]:
    """
    云函数入口

    支持的触发方式：
    1. 定时触发 - 自动检查续期
    2. API 网关触发 - 手动操作

    Args:
        event: 事件数据
        context: 上下文

    Returns:
        响应结果
    """
    logger.info(f'Received event: {json.dumps(event, ensure_ascii=False)}')

    try:
        # 定时触发器触发
        if 'Message' in event:
            message = json.loads(event['Message'])
            if message.get('Type') == 'Timer':
                return check_and_renew()

        # API 网关触发
        if 'httpMethod' in event:
            # 解析 API 网关事件
            path = event.get('path', '')
            method = event.get('httpMethod', 'GET')

            # 解析 body
            body = {}
            if event.get('body'):
                try:
                    body = json.loads(event['body'])
                except json.JSONDecodeError:
                    pass

            # 获取查询参数
            query_params = event.get('queryString', {}) or event.get('queryStringParameters', {})

            # 路由处理
            if path == '/certificate/issue' and method == 'POST':
                domain = body.get('domain') or query_params.get('domain')
                staging = body.get('staging', False) or query_params.get('staging') == 'true'
                if not domain:
                    return Response.error('Domain is required', 400)
                return issue_new_certificate(domain, staging)

            elif path == '/certificate/renew' and method == 'POST':
                domain = body.get('domain') or query_params.get('domain')
                force = body.get('force', False) or query_params.get('force') == 'true'
                if not domain:
                    return Response.error('Domain is required', 400)
                return renew_certificate(domain, force)

            elif path == '/certificate/deploy' and method == 'POST':
                domain = body.get('domain')
                resource_type = body.get('resourceType')
                resource_ids = body.get('resourceIds', [])
                if not domain or not resource_type or not resource_ids:
                    return Response.error('domain, resourceType, and resourceIds are required', 400)
                return deploy_certificate(domain, resource_type, resource_ids)

            elif path == '/certificate/list' and method == 'GET':
                domain = query_params.get('domain')
                return list_certificates(domain)

            else:
                return Response.error('Not found', 404)

        # 直接调用（event 中包含 action）
        if isinstance(event, dict):
            action = event.get('action')

            if action == 'issue':
                domain = event.get('domain')
                staging = event.get('staging', False)
                if not domain:
                    return Response.error('Domain is required', 400)
                return issue_new_certificate(domain, staging)

            elif action == 'renew':
                domain = event.get('domain')
                force = event.get('force', False)
                if not domain:
                    return Response.error('Domain is required', 400)
                return renew_certificate(domain, force)

            elif action == 'deploy':
                domain = event.get('domain')
                resource_type = event.get('resourceType')
                resource_ids = event.get('resourceIds', [])
                if not domain or not resource_type or not resource_ids:
                    return Response.error('domain, resourceType, and resourceIds are required', 400)
                return deploy_certificate(domain, resource_type, resource_ids)

            elif action == 'list':
                domain = event.get('domain')
                return list_certificates(domain)

            elif action == 'check':
                return check_and_renew()

            elif action == 'upload':
                domain = event.get('domain')
                cert_dir = event.get('certDir')
                if not domain:
                    return Response.error('Domain is required', 400)
                return upload_existing_certificate(domain, cert_dir)

        # 默认：检查续期
        return check_and_renew()

    except Exception as e:
        logger.error(f'Error in main_handler: {e}')
        logger.error(traceback.format_exc())
        return Response.error(
            f'Internal server error: {str(e)}',
            500
        )


# 本地测试入口
if __name__ == '__main__':
    # 本地测试代码
    import sys
    import argparse

    # 创建命令行解析器
    parser = argparse.ArgumentParser(
        description='Let\'s Encrypt 证书管理工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  python index.py issue-local cdn.example.com              # 本地申请证书（测试环境）
  python index.py issue-local cdn.example.com --email user@example.com  # 指定邮箱
  python index.py issue-local cdn.example.com --production # 使用生产环境
  python index.py issue cdn.example.com                    # 申请并上传到腾讯云
  python index.py upload cdn.example.com                  # 上传已有证书到腾讯云
  python index.py renew cdn.example.com                    # 续期证书
  python index.py list                                      # 列出证书
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='可用命令')

    # issue-local 命令
    issue_local_parser = subparsers.add_parser('issue-local', help='本地申请证书（不上传到腾讯云）')
    issue_local_parser.add_argument('domain', help='域名')
    issue_local_parser.add_argument('--email', help='ACME 账户邮箱')
    issue_local_parser.add_argument('--production', action='store_true', help='使用生产环境（默认使用测试环境）')
    issue_local_parser.add_argument('--work-dir', help='证书保存目录（默认: ./certs）')

    # issue 命令
    issue_parser = subparsers.add_parser('issue', help='申请证书并上传到腾讯云')
    issue_parser.add_argument('domain', help='域名')
    issue_parser.add_argument('--production', action='store_true', help='使用生产环境（默认使用测试环境）')

    # renew 命令
    renew_parser = subparsers.add_parser('renew', help='续期证书')
    renew_parser.add_argument('domain', help='域名')
    renew_parser.add_argument('--force', action='store_true', help='强制续期')

    # list 命令
    subparsers.add_parser('list', help='列出证书')

    # check 命令
    subparsers.add_parser('check', help='检查并续期即将过期的证书')

    # upload 命令
    upload_parser = subparsers.add_parser('upload', help='上传已有证书到腾讯云')
    upload_parser.add_argument('domain', help='域名')
    upload_parser.add_argument('--cert-dir', help='证书目录（默认: ./certs/{domain}）')

    # 解析参数
    args = parser.parse_args()

    # 如果没有指定命令，显示帮助
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # 尝试加载 .env 文件
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    # 处理 issue-local 命令（本地申请，不上传到腾讯云）
    if args.command == 'issue-local':
        staging = not args.production
        result = issue_certificate_local(
            domain=args.domain,
            email=args.email,
            staging=staging
        )
        body = json.loads(result['body'])
        if body.get('success'):
            print('=' * 60)
            print('证书申请成功！')
            print('=' * 60)
            print(f"域名: {body['data'].get('domain')}")
            print(f"证书路径: {body['data'].get('cert_path')}")
            print(f"私钥路径: {body['data'].get('key_path')}")
            if body['data'].get('expiry_date'):
                print(f"过期时间: {body['data'].get('expiry_date')}")
                print(f"剩余天数: {body['data'].get('remaining_days')}")
            print(f"环境: {'测试环境' if staging else '生产环境'}")
            print('=' * 60)
        else:
            print(f"错误: {body.get('message')}")
            sys.exit(1)
        sys.exit(0)

    # 其他命令通过 main_handler 处理
    event = {}
    if args.command == 'issue':
        event = {'action': 'issue', 'domain': args.domain, 'staging': not args.production}
    elif args.command == 'renew':
        event = {'action': 'renew', 'domain': args.domain, 'force': args.force}
    elif args.command == 'list':
        event = {'action': 'list'}
    elif args.command == 'check':
        event = {'action': 'check'}
    elif args.command == 'upload':
        event = {'action': 'upload', 'domain': args.domain, 'certDir': getattr(args, 'cert_dir', None)}

    # 执行
    result = main_handler(event, {})
    print(json.dumps(json.loads(result['body']), indent=2, ensure_ascii=False))
