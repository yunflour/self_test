#!/usr/bin/env python3
"""
上传账号到发卡平台
由批量注册脚本调用，或单独使用
"""

import argparse
import json
import sys
from pathlib import Path

import requests


def login(base_url: str, username: str, password: str) -> requests.Session:
    """登录发卡平台，返回已认证的 session"""
    session = requests.Session()
    login_url = f"{base_url.rstrip('/')}/admin/login"
    resp = session.post(login_url, json={"username": username, "password": password})
    if resp.status_code != 200 or not resp.json().get("success"):
        raise RuntimeError(f"登录失败: {resp.text}")
    return session


def upload_account(
    session: requests.Session,
    base_url: str,
    email: str,
    access_token: str = None,
    refresh_token: str = None,
    id_token: str = None,
    token_data: dict = None,
) -> dict:
    """上传单个账号到发卡平台"""
    url = f"{base_url.rstrip('/')}/api/admin/accounts"
    payload = {
        "email": email,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
    }
    if token_data:
        payload["accounts"] = [token_data]

    resp = session.post(url, json=payload)
    return resp.json()


def upload_accounts(session: requests.Session, base_url: str, accounts: list[dict]) -> dict:
    """批量上传多个账号到发卡平台"""
    url = f"{base_url.rstrip('/')}/api/admin/accounts"
    resp = session.post(url, json={"accounts": accounts})
    return resp.json()


def load_result_account(result_file: str) -> dict:
    """从结果文件提取单个账号信息"""
    with open(result_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    token_output = data.get("token_output", {})
    if not isinstance(token_output, dict):
        token_output = {}

    email = token_output.get("email") or data.get("email")
    if not email:
        raise ValueError(f"未找到邮箱: {result_file}")

    token_data = {
        "email": email,
        "access_token": token_output.get("access_token"),
        "refresh_token": token_output.get("refresh_token"),
        "id_token": token_output.get("id_token"),
        "client_id": token_output.get("client_id"),
        "client_secret": token_output.get("client_secret"),
        "profile_arn": token_output.get("profile_arn"),
        "region": token_output.get("region"),
        "start_url": token_output.get("start_url"),
    }
    return {k: v for k, v in token_data.items() if v is not None}


def load_token_account(token_file: str, email: str = None) -> dict:
    """从 token 文件提取单个账号信息"""
    with open(token_file, "r", encoding="utf-8") as f:
        token_data = json.load(f)

    if not isinstance(token_data, dict):
        raise ValueError(f"token 文件格式错误: {token_file}")

    resolved_email = email or token_data.get("email")
    if not resolved_email:
        raise ValueError(f"未指定邮箱: {token_file}")

    token_data["email"] = resolved_email
    return {k: v for k, v in token_data.items() if v is not None}


def upload_from_result_file(
    session: requests.Session,
    base_url: str,
    result_file: str,
) -> dict:
    """从 kiro-zhuce 的结果文件上传账号"""
    try:
        token_data = load_result_account(result_file)
    except Exception as e:
        return {"success": False, "error": str(e)}

    email = token_data["email"]
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    id_token = token_data.get("id_token")

    return upload_account(
        session=session,
        base_url=base_url,
        email=email,
        access_token=access_token,
        refresh_token=refresh_token,
        id_token=id_token,
        token_data=token_data,
    )


def collect_files(dir_path: str) -> list[Path]:
    """收集目录下的 JSON 文件"""
    base = Path(dir_path)
    if not base.is_dir():
        raise ValueError(f"不是目录: {dir_path}")
    return sorted(p for p in base.iterdir() if p.is_file() and p.suffix.lower() == ".json")


def upload_from_result_dir(session: requests.Session, base_url: str, result_dir: str) -> dict:
    """批量上传结果目录中的所有账号"""
    files = collect_files(result_dir)
    accounts = []
    errors = []

    for path in files:
        try:
            accounts.append(load_result_account(str(path)))
        except Exception as e:
            errors.append({"file": str(path), "error": str(e)})

    if not accounts:
        return {"success": False, "error": "目录中没有可上传的结果文件", "failed": errors}

    result = upload_accounts(session, base_url, accounts)
    if errors:
        failed = result.get("failed")
        if isinstance(failed, list):
            failed.extend(errors)
        else:
            result["failed"] = errors
    return result


def upload_from_token_dir(session: requests.Session, base_url: str, token_dir: str) -> dict:
    """批量上传 token 目录中的所有账号"""
    files = collect_files(token_dir)
    accounts = []
    errors = []

    for path in files:
        try:
            accounts.append(load_token_account(str(path)))
        except Exception as e:
            errors.append({"file": str(path), "error": str(e)})

    if not accounts:
        return {"success": False, "error": "目录中没有可上传的 token 文件", "failed": errors}

    result = upload_accounts(session, base_url, accounts)
    if errors:
        failed = result.get("failed")
        if isinstance(failed, list):
            failed.extend(errors)
        else:
            result["failed"] = errors
    return result


def main():
    parser = argparse.ArgumentParser(description="上传账号到发卡平台")
    parser.add_argument("--url", required=True, help="发卡平台地址")
    parser.add_argument("--username", required=True, help="管理员用户名")
    parser.add_argument("--password", required=True, help="管理员密码")
    parser.add_argument("--result-file", help="kiro-zhuce 结果文件路径")
    parser.add_argument("--result-dir", help="批量上传结果目录中的所有 JSON 文件")
    parser.add_argument("--token-file", help="token JSON 文件路径")
    parser.add_argument("--token-dir", help="批量上传 token 目录中的所有 JSON 文件")
    parser.add_argument("--email", help="账号邮箱（直接指定时使用）")
    args = parser.parse_args()

    session = login(args.url, args.username, args.password)

    if args.result_dir:
        result = upload_from_result_dir(session, args.url, args.result_dir)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.result_file:
        result = upload_from_result_file(session, args.url, args.result_file)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.token_dir:
        result = upload_from_token_dir(session, args.url, args.token_dir)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.token_file:
        try:
            token_data = load_token_account(args.token_file, args.email)
        except Exception as e:
            print(json.dumps({"success": False, "error": str(e)}, ensure_ascii=False, indent=2))
            sys.exit(1)

        result = upload_account(
            session=session,
            base_url=args.url,
            email=token_data["email"],
            token_data=token_data,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print(json.dumps({"success": False, "error": "请指定 --result-file、--result-dir、--token-file 或 --token-dir"}, ensure_ascii=False, indent=2))
    sys.exit(1)


if __name__ == "__main__":
    main()
