#!/usr/bin/env python3
"""
上传账号到发卡平台
由批量注册脚本调用，或单独使用
"""

import argparse
import json
import os
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


def upload_from_result_file(
    session: requests.Session,
    base_url: str,
    result_file: str,
) -> dict:
    """从 kiro-zhuce 的结果文件上传账号"""
    with open(result_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 提取账号信息
    token_output = data.get("token_output", {})
    if not isinstance(token_output, dict):
        token_output = {}

    email = token_output.get("email") or data.get("email")
    if not email:
        return {"success": False, "error": "未找到邮箱"}

    access_token = token_output.get("access_token")
    refresh_token = token_output.get("refresh_token")
    id_token = token_output.get("id_token")

    # 构建完整的 token_data
    token_data = {
        "email": email,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "client_id": token_output.get("client_id"),
        "client_secret": token_output.get("client_secret"),
        "profile_arn": token_output.get("profile_arn"),
        "region": token_output.get("region"),
        "start_url": token_output.get("start_url"),
    }
    # 过滤掉 None 值
    token_data = {k: v for k, v in token_data.items() if v is not None}

    return upload_account(
        session=session,
        base_url=base_url,
        email=email,
        access_token=access_token,
        refresh_token=refresh_token,
        id_token=id_token,
        token_data=token_data,
    )


def main():
    parser = argparse.ArgumentParser(description="上传账号到发卡平台")
    parser.add_argument("--url", required=True, help="发卡平台地址")
    parser.add_argument("--username", required=True, help="管理员用户名")
    parser.add_argument("--password", required=True, help="管理员密码")
    parser.add_argument("--result-file", help="kiro-zhuce 结果文件路径")
    parser.add_argument("--token-file", help="token JSON 文件路径")
    parser.add_argument("--email", help="账号邮箱（直接指定时使用）")
    args = parser.parse_args()

    session = login(args.url, args.username, args.password)

    if args.result_file:
        result = upload_from_result_file(session, args.url, args.result_file)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.token_file:
        with open(args.token_file, "r", encoding="utf-8") as f:
            token_data = json.load(f)
        email = args.email or token_data.get("email")
        if not email:
            print(json.dumps({"success": False, "error": "未指定邮箱"}))
            sys.exit(1)
        result = upload_account(
            session=session,
            base_url=args.url,
            email=email,
            token_data=token_data,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print(json.dumps({"success": False, "error": "请指定 --result-file 或 --token-file"}))
    sys.exit(1)


if __name__ == "__main__":
    main()
