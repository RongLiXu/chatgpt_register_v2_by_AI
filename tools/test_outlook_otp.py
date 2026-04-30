import argparse
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from lib.clients import CloudMailService


def parse_outlook_line(line: str):
    value = str(line or "").strip().lstrip("\ufeff")
    if not value:
        raise ValueError("账号行为空")

    parts = value.split("----")
    if len(parts) < 4:
        raise ValueError("Outlook 账号格式必须为: 账号----密码----邮箱密码----rt")

    email = str(parts[0] or "").strip().lower()
    openai_password = str(parts[1] or "").strip()
    mailbox_password = str(parts[2] or "").strip()
    rt = str(parts[3] or "").strip()

    if not email.endswith("@outlook.com"):
        raise ValueError("该测试脚本仅支持 @outlook.com")
    if not openai_password or not mailbox_password:
        raise ValueError("账号密码或邮箱密码为空")

    return email, openai_password, mailbox_password, rt


def main():
    parser = argparse.ArgumentParser(description="最小 Outlook 邮箱验证码测试")
    parser.add_argument(
        "-f",
        "--file",
        default="accounts/outlook-207260406083646398-1.txt",
        help="Outlook 账号文件，默认读取 accounts/outlook-207260406083646398-1.txt",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        help="等待超时时间（秒）",
    )
    args = parser.parse_args()

    with open(args.file, "r", encoding="utf-8") as f:
        first_line = ""
        for line in f:
            if str(line or "").strip():
                first_line = line
                break

    if not first_line:
        raise ValueError(f"文件为空: {args.file}")

    email, _, mailbox_password, rt = parse_outlook_line(first_line)

    service = CloudMailService(
        config={
            "base_url": "https://placeholder.local",
            "admin_password": "placeholder",
        }
    )

    code = service.get_outlook_verification_code(
        email=email,
        email_password=mailbox_password,
        timeout=args.timeout,
        pattern=r"(?<!\d)(\d{6})(?!\d)",
        otp_sent_at=None,
        rt=rt,
    )

    if not code:
        print("未获取到验证码")
        sys.exit(1)

    if not re.fullmatch(r"\d{6}", code):
        print(f"获取结果不是 6 位验证码: {code}")
        sys.exit(1)

    print(f"获取成功: {email} -> {code}")


if __name__ == "__main__":
    main()
