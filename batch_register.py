#!/usr/bin/env python3
"""
批量并发执行 kiro_full_flow_cn.py，并汇总注册结果。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

import requests

# 全局日志文件路径和锁
_log_file_path: str | None = None
_log_lock = threading.Lock()

# 发卡平台配置（全局）
_faka_url: str | None = None
_faka_username: str | None = None
_faka_password: str | None = None
_faka_session: requests.Session | None = None


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def log(msg: str) -> None:
    """打印日志到控制台，同时写入log文件"""
    log_line = f"[{now_str()}] {msg}"
    print(log_line)
    if _log_file_path:
        with _log_lock:
            with open(_log_file_path, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")


def normalize_run_id(value: str) -> str:
    base = value.strip()
    base = re.sub(r"[^a-zA-Z0-9._-]", "-", base)
    base = re.sub(r"-+", "-", base).strip("-")
    return base or "run"


def extract_result_file(output: str) -> str | None:
    pattern = re.compile(r"完整结果文件已保存：(.+)$", re.MULTILINE)
    match = pattern.search(output)
    if not match:
        return None
    return match.group(1).strip()


def load_json(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        log(f"加载 JSON 文件失败: {path}, 错误: {e}")
        return {}


def faka_login() -> requests.Session | None:
    """登录发卡平台，返回已认证的 session"""
    global _faka_session
    if not _faka_url or not _faka_username or not _faka_password:
        return None
    if _faka_session:
        return _faka_session
    try:
        session = requests.Session()
        login_url = f"{_faka_url.rstrip('/')}/admin/login"
        resp = session.post(login_url, json={"username": _faka_username, "password": _faka_password}, timeout=30)
        if resp.status_code == 200 and resp.json().get("success"):
            _faka_session = session
            return session
        else:
            log(f"发卡平台登录失败: {resp.text}")
            return None
    except Exception as e:
        log(f"发卡平台登录异常: {e}")
        return None


def upload_to_faka(result_file: str) -> bool:
    """上传账号到发卡平台"""
    session = faka_login()
    if not session:
        return False

    try:
        with open(result_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log(f"读取结果文件失败: {e}")
        return False

    token_output = data.get("token_output", {})
    if not isinstance(token_output, dict):
        token_output = {}

    email = token_output.get("email") or data.get("email")
    if not email:
        log(f"结果文件中未找到邮箱: {result_file}")
        return False

    access_token = token_output.get("access_token")
    refresh_token = token_output.get("refresh_token")
    id_token = token_output.get("id_token")

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
    token_data = {k: v for k, v in token_data.items() if v is not None}

    try:
        url = f"{_faka_url.rstrip('/')}/api/admin/accounts"
        resp = session.post(url, json={"accounts": [token_data]}, timeout=30)
        result = resp.json()
        if result.get("success"):
            imported = result.get("imported", [])
            if imported:
                log(f"上传发卡平台成功: {email}")
                return True
            else:
                failed = result.get("failed", [])
                if failed:
                    log(f"上传发卡平台失败: {failed[0].get('error', '未知错误')}")
                return False
        else:
            log(f"上传发卡平台失败: {result.get('error', '未知错误')}")
            return False
    except Exception as e:
        log(f"上传发卡平台异常: {e}")
        return False


def classify_result(result_json: dict[str, Any]) -> dict[str, str]:
    # 优先检测 IP 封禁
    if result_json.get("ip_blocked"):
        return {"status": "ban"}

    verify = result_json.get("credential_verify")
    if isinstance(verify, dict):
        status = str(verify.get("status", "unknown") or "unknown")
    else:
        status = "unknown"

    if status == "ok":
        return {"status": "ok"}
    if status == "blocked_or_invalid":
        return {"status": "blocked"}
    if "error" in result_json:
        return {"status": "failed"}
    return {"status": "unknown"}


def run_one(
    run_id: str,
    idx: int,
    total: int,
    python_exe: str,
    script_path: str,
    env: dict[str, str],
    lock: threading.Lock,
) -> dict[str, Any]:
    tag = f"{run_id}-{idx}"
    log(f"[{idx}/{total}] 开始任务 {tag}")
    job_env = dict(env)
    job_env["KIRO_RUN_ID"] = tag

    try:
        completed = subprocess.run(
            [python_exe, script_path],
            env=job_env,
            capture_output=True,
            text=True,
            timeout=None,
        )
        output = "".join([completed.stdout or "", completed.stderr or ""])
        # 将子进程输出写入日志文件
        if _log_file_path and output:
            with _log_lock:
                with open(_log_file_path, "a", encoding="utf-8") as f:
                    f.write(f"\n{'=' * 40}\n")
                    f.write(f"[{tag}] 子进程输出:\n")
                    f.write(f"{'=' * 40}\n")
                    f.write(output)
                    if not output.endswith("\n"):
                        f.write("\n")

        result_file = extract_result_file(output)
        if result_file and os.path.exists(result_file):
            result_json = load_json(result_file)
            classification = classify_result(result_json)
            token_file = result_json.get("token_output_file", "")
            email = ""
            token_output = result_json.get("token_output")
            if isinstance(token_output, dict):
                email = token_output.get("email", "")
            status = classification["status"]
            log(f"[{idx}/{total}] 任务 {tag} 完成: status={status}, email={email}")

            # 上传到发卡平台（仅成功时）
            faka_uploaded = False
            if status == "ok" and _faka_url:
                faka_uploaded = upload_to_faka(result_file)

            return {
                "id": tag,
                "status": status,
                "result_file": result_file,
                "token_file": token_file,
                "email": email,
                "faka_uploaded": faka_uploaded,
            }

        with lock:
            log(f"[{idx}/{total}] 任务 {tag} 未找到结果文件，标记为 failed")
        return {"id": tag, "status": "failed"}

    except Exception as e:
        log(f"[{idx}/{total}] 任务 {tag} 执行异常: {e}")
        return {"id": tag, "status": "failed", "error": str(e)}


def print_table(rows: list[dict[str, Any]]) -> None:
    total = len(rows)
    ok = sum(1 for r in rows if r.get("status") == "ok")
    blocked = sum(1 for r in rows if r.get("status") == "blocked")
    ban = sum(1 for r in rows if r.get("status") == "ban")
    failed = sum(1 for r in rows if r.get("status") == "failed")
    unknown = sum(1 for r in rows if r.get("status") == "unknown")

    header = ["total", "ok", "blocked", "ban", "failed", "unknown"]
    values = [str(total), str(ok), str(blocked), str(ban), str(failed), str(unknown)]
    widths = [max(len(h), len(v)) for h, v in zip(header, values)]

    line = " | ".join(h.ljust(w) for h, w in zip(header, widths))
    sep = "-+-".join("-" * w for w in widths)
    val = " | ".join(v.ljust(w) for v, w in zip(values, widths))

    log("")
    log("=" * 60)
    log("结果汇总")
    log("=" * 60)
    log(line)
    log(sep)
    log(val)

    # 逐条打印详情
    log("详细列表：")
    log("-" * 60)
    sorted_rows = sorted(rows, key=lambda r: r.get("id", ""))
    for r in sorted_rows:
        status = r.get("status", "unknown")
        tag = r.get("id", "?")
        email = r.get("email", "")
        token_file = r.get("token_file", "")
        faka_uploaded = r.get("faka_uploaded", False)
        status_icon = {"ok": "✓", "blocked": "✗", "ban": "⛔", "failed": "✗", "unknown": "?"}.get(
            status, "?"
        )
        parts = [f"  {status_icon} [{status:>7s}] {tag}"]
        if email:
            parts.append(f"    邮箱: {email}")
        if token_file:
            parts.append(f"    文件: {token_file}")
        if status == "ok" and _faka_url:
            upload_icon = "↑" if faka_uploaded else "✗"
            parts.append(f"    发卡: {upload_icon}")
        log("\n".join(parts))
    log("-" * 60)


def main() -> None:
    global _log_file_path, _faka_url, _faka_username, _faka_password

    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--python", default="python3")
    parser.add_argument(
        "--script",
        default=os.path.join(os.getcwd(), "kiro_full_flow_cn.py"),
    )
    parser.add_argument("--run-id", default="batch")
    parser.add_argument("--faka-url", help="发卡平台地址，如 https://faka.example.com")
    parser.add_argument("--faka-username", help="发卡平台管理员用户名")
    parser.add_argument("--faka-password", help="发卡平台管理员密码")
    args = parser.parse_args()

    if args.count < 1:
        raise SystemExit("--count 必须 >= 1")
    if args.workers < 1:
        raise SystemExit("--workers 必须 >= 1")

    run_id = normalize_run_id(args.run_id)
    env = os.environ.copy()
    lock = threading.Lock()

    # 设置发卡平台配置
    _faka_url = args.faka_url
    _faka_username = args.faka_username
    _faka_password = args.faka_password

    # 创建data目录和log文件
    data_dir = os.path.join(os.getcwd(), "data")
    os.makedirs(data_dir, exist_ok=True)
    log_filename = datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"
    _log_file_path = os.path.join(data_dir, log_filename)

    log(f"批量注册开始: count={args.count}, workers={args.workers}, run-id={run_id}")
    if _faka_url:
        log(f"发卡平台: {_faka_url}")
    log(f"日志文件: {_log_file_path}")
    start_time = time.time()

    rows: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = []
        for idx in range(args.count):
            futures.append(
                executor.submit(
                    run_one,
                    run_id,
                    idx + 1,
                    args.count,
                    args.python,
                    args.script,
                    env,
                    lock,
                )
            )
            if idx < args.count - 1:
                time.sleep(1)
        for fut in as_completed(futures):
            try:
                result = fut.result()
                rows.append(result)
                log(f"已收集 {len(rows)}/{args.count} 个任务结果")
            except Exception as e:
                log(f"获取任务结果异常: {e}")
                rows.append({"id": "unknown", "status": "failed", "error": str(e)})

    log(f"所有任务已完成，共收集 {len(rows)} 个结果，开始汇总...")
    elapsed = time.time() - start_time
    print_table(rows)

    ok_count = sum(1 for r in rows if r.get("status") == "ok")
    if ok_count > 0:
        log(f"成功: {ok_count} 个，token 文件已保存在 data/ok/ 目录")

    log(f"总耗时: {elapsed:.1f} 秒")


if __name__ == "__main__":
    main()
