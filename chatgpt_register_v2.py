"""
ChatGPT 批量登录获取 Token 工具 v2.0 - 模块化版本
使用本地账号密码 + CloudMail OTP，并发获取 OAuth Token
"""

import os
import sys
import time
import threading
import argparse
import warnings
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# 强制使用 UTF-8 输出
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# 禁用 SSL 警告
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# 将项目根目录添加到 sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入自定义模块
from lib.utils import load_config, as_bool
from lib.clients import TokenManager

# 导入引擎模块
from lib.core import RegistrationEngine
from lib.clients import CloudMailService

# 全局文件写入锁
_file_lock = threading.Lock()

def init_cloudmail_client(config):
    cloud_mail_config = {
        "base_url": config.get("cloudmail_url", ""),
        "admin_email": config.get("cloudmail_admin_email", ""),
        "admin_password": config.get("cloudmail_admin_password", ""),
        "domain": config.get("cloudmail_domains", []),
        "subdomain": config.get("cloudmail_subdomain", ""),
        "timeout": config.get("timeout", 30),
        "proxy_url": config.get("proxy", "")
    }
    return CloudMailService(config=cloud_mail_config)

def parse_account_line(line):
    """解析账号行，支持 email----password、email,password、email password。"""
    value = str(line or "").strip().lstrip("\ufeff")
    if not value or value.startswith("#"):
        return None

    if "----" in value:
        parts = value.split("----")
    elif "," in value:
        parts = value.split(",")
    else:
        parts = re.split(r"\s+", value, maxsplit=1)

    if len(parts) < 2:
        raise ValueError(f"账号行格式错误: {line.rstrip()}")

    email = str(parts[0] or "").strip().lower()
    password = str(parts[1] or "").strip()
    if not email or not password:
        raise ValueError(f"账号行缺少邮箱或密码: {line.rstrip()}")
    return email, password


def load_account_credentials(input_file):
    """从本地文件读取邮箱密码。"""
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"账号文件不存在: {input_file}")

    accounts = []
    with open(input_file, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            try:
                parsed = parse_account_line(line)
            except ValueError as e:
                raise ValueError(f"{input_file}:{line_no}: {e}") from e
            if parsed:
                accounts.append(parsed)

    if not accounts:
        raise ValueError(f"账号文件为空: {input_file}")
    return accounts


def normalize_failure_reason(reason):
    """清理失败原因，避免写入多行破坏结果文件格式。"""
    text = str(reason or "unknown").strip()
    text = re.sub(r"\s+", " ", text)
    return text or "unknown"


def save_failed_account(output_file, email, password, reason):
    """记录失败账号和原因。"""
    with _file_lock:
        with open(output_file, "a", encoding="utf-8") as f:
            f.write(f"{email}----{password}----failed={normalize_failure_reason(reason)}\n")


def login_one_account(idx, total, account, cloudmail_client, token_manager, config):
    """
    登录单个账号并获取 OAuth Token。
    
    Args:
        idx: 账号序号
        total: 总账号数
        account: (email, password)
        cloudmail_client: CloudMail 客户端
        token_manager: Token 管理器
        config: 配置字典
        
    Returns:
        tuple: (success, email, password, message)
    """
    tag = f"[{idx}/{total}]"
    email, password = account
    print(f"\n{tag} 开始登录获取 Token: {email}")
    
    try:
        # 1. 准备配置信息
        proxy = config.get("proxy", "")
        enable_oauth = as_bool(config.get("enable_oauth", True))
        oauth_required = as_bool(config.get("oauth_required", True))
        output_file = config.get("output_file", "registered_accounts.txt")
        failed_output_file = config.get("failed_output_file", "failed_accounts.txt")
        
        # 定义一个简单的回调日志来将 RegistrationEngine 的输出带上标签
        def callback_logger(msg):
            print(f"{tag} {msg}")

        # 2. 创建登录引擎
        engine = RegistrationEngine(
            email_service=cloudmail_client,
            proxy_url=proxy,
            callback_logger=callback_logger
        )
        
        # 3. 执行本地账号登录流程
        print(f"{tag} 开始执行本地账号登录流程...")
        result = engine.run_login(email, password)
        
        email = result.email
        password = result.password
        
        if not result.success:
            print(f"{tag} ❌ 登录失败: {result.error_message}")
            save_failed_account(failed_output_file, email, password, result.error_message)
            return False, email, password, result.error_message
            
        print(f"{tag} ✅ 登录成功 (账户: {email})")
        
        # 4. 判断并保存 OAuth Token
        has_token = bool(result.access_token)
        
        if enable_oauth:
            if has_token:
                print(f"{tag} ✅ OAuth 成功")
                print(f"{tag} 8、登录成功后写入 output_file、ak.txt、rk.txt 和 tokens/ 目录")
                # 组装 tokens 给 token_manager
                tokens = {
                    "access_token": result.access_token,
                    "refresh_token": getattr(result, "refresh_token", ""),
                    "id_token": getattr(result, "id_token", ""),
                    "session_token": getattr(result, "session_token", "")
                }
                token_manager.save_tokens(email, tokens)
                
                # 保存账号信息
                with _file_lock:
                    with open(output_file, "a", encoding="utf-8") as f:
                        f.write(f"{email}----{password}----oauth=ok\n")
                
                return True, email, password, "登录成功 + OAuth 成功"
            else:
                print(f"{tag} ⚠️ OAuth 失败或未能获取")
                if oauth_required:
                    reason = "OAuth 失败（必需）"
                    save_failed_account(failed_output_file, email, password, reason)
                    return False, email, password, reason
                else:
                    print(f"{tag} 8、登录成功后写入 output_file，token 文件因 OAuth 失败不写入")
                    # 保存账号信息（无 OAuth）
                    with _file_lock:
                        with open(output_file, "a", encoding="utf-8") as f:
                            f.write(f"{email}----{password}----oauth=failed\n")
                    return True, email, password, "登录成功（OAuth 失败）"
        else:
            print(f"{tag} 8、登录成功后写入 output_file，当前已禁用 OAuth token 保存")
            # 不启用 OAuth 或者不关心 OAuth 结果，直接保存账号
            with _file_lock:
                with open(output_file, "a", encoding="utf-8") as f:
                    f.write(f"{email}----{password}\n")
            return True, email, password, "登录成功"
            
    except Exception as e:
        print(f"{tag} ❌ 登录失败: {e}")
        save_failed_account(config.get("failed_output_file", "failed_accounts.txt"), email, password, e)
        import traceback
        traceback.print_exc()
        return False, email, password, str(e)


def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='ChatGPT 批量登录获取 Token 工具 v2.0')
    parser.add_argument('-i', '--input-file', default="", help='本地账号文件（默认读取配置 input_file 或 accounts.txt）')
    parser.add_argument('-n', '--num', type=int, default=0, help='处理账号数量（默认: 0，表示全部）')
    parser.add_argument('-w', '--workers', type=int, default=1, help='并发线程数（默认: 1）')
    parser.add_argument('--no-oauth', action='store_true', help='禁用 OAuth 登录')
    args = parser.parse_args()
    
    print("=" * 60)
    print("  ChatGPT 批量登录获取 Token 工具 v2.0 (模块化版本)")
    print("  使用本地账号密码 + CloudMail OTP")
    print("=" * 60)
    
    # 加载配置
    config = load_config()
    
    input_file = args.input_file or config.get("input_file", "accounts.txt")
    accounts = load_account_credentials(input_file)
    if args.num and args.num > 0:
        accounts = accounts[:args.num]

    # 命令行参数覆盖配置文件
    total_accounts = len(accounts)
    max_workers = args.workers
    if args.no_oauth:
        config['enable_oauth'] = False
    
    # 初始化 CloudMail 客户端
    cloudmail_client = init_cloudmail_client(config)
    
    # 初始化 Token 管理器
    token_manager = TokenManager(config)
    
    # 获取配置参数
    output_file = config.get("output_file", "registered_accounts.txt")
    failed_output_file = config.get("failed_output_file", "failed_accounts.txt")
    enable_oauth = as_bool(config.get("enable_oauth", True))
    
    print(f"\n配置信息:")
    print(f"  账号文件: {input_file}")
    print(f"  登录数量: {total_accounts}")
    print(f"  并发数: {max_workers}")
    print(f"  输出文件: {output_file}")
    print(f"  失败文件: {failed_output_file}")
    print(f"  CloudMail API: {cloudmail_client.config.get('base_url', '')}")
    print(f"  Token 目录: {token_manager.token_dir}")
    print(f"  启用 OAuth: {enable_oauth}")
    print()
    
    # 批量登录
    success_count = 0
    failed_count = 0
    start_time = time.time()
    
    if max_workers == 1:
        # 串行执行
        for i, account in enumerate(accounts, 1):
            success, email, password, msg = login_one_account(
                i, total_accounts, account, cloudmail_client, token_manager, config
            )
            if success:
                success_count += 1
            else:
                failed_count += 1
    else:
        # 并发执行
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for i, account in enumerate(accounts, 1):
                future = executor.submit(
                    login_one_account,
                    i, total_accounts, account, cloudmail_client, token_manager, config
                )
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    success, email, password, msg = future.result()
                    if success:
                        success_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    print(f"❌ 任务异常: {e}")
                    failed_count += 1
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # 输出统计
    print("\n" + "=" * 60)
    print(f"登录完成！")
    print(f"  成功: {success_count}")
    print(f"  失败: {failed_count}")
    print(f"  总计: {total_accounts}")
    print(f"  总耗时: {total_time:.1f}s")
    if success_count > 0:
        print(f"  平均耗时: {total_time/total_accounts:.1f}s/账号")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n程序异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
