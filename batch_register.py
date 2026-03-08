#!/usr/bin/env python3
"""
批量并发执行 kiro_full_flow_cn.py，并汇总注册结果。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

# 全局日志文件路径和锁
_log_file_path: str | None = None
_log_lock = threading.Lock()


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
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def classify_result(result_json: dict[str, Any]) -> dict[str, str]:
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
    except Exception as e:
        log(f"[{idx}/{total}] 任务 {tag} 执行异常: {e}")
        return {"id": tag, "status": "failed", "error": str(e)}

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
        return {
            "id": tag,
            "status": status,
            "result_file": result_file,
            "token_file": token_file,
            "email": email,
        }

    with lock:
        log(f"[{idx}/{total}] 任务 {tag} 未找到结果文件，标记为 failed")
    return {"id": tag, "status": "failed"}


def print_table(rows: list[dict[str, Any]]) -> None:
    total = len(rows)
    blocked = sum(1 for r in rows if r.get("status") == "blocked")
    ok = sum(1 for r in rows if r.get("status") == "ok")
    failed = sum(1 for r in rows if r.get("status") == "failed")
    unknown = sum(1 for r in rows if r.get("status") == "unknown")

    header = ["total", "ok", "blocked", "failed", "unknown"]
    values = [str(total), str(ok), str(blocked), str(failed), str(unknown)]
    widths = [max(len(h), len(v)) for h, v in zip(header, values)]

    line = " | ".join(h.ljust(w) for h, w in zip(header, widths))
    sep = "-+-".join("-" * w for w in widths)
    val = " | ".join(v.ljust(w) for v, w in zip(values, widths))

    print("\n" + "=" * 60)
    print("结果汇总")
    print("=" * 60)
    print(line)
    print(sep)
    print(val)

    # 逐条打印详情
    print("\n详细列表：")
    print("-" * 60)
    sorted_rows = sorted(rows, key=lambda r: r.get("id", ""))
    for r in sorted_rows:
        status = r.get("status", "unknown")
        tag = r.get("id", "?")
        email = r.get("email", "")
        token_file = r.get("token_file", "")
        status_icon = {"ok": "✓", "blocked": "✗", "failed": "✗", "unknown": "?"}.get(
            status, "?"
        )
        parts = [f"  {status_icon} [{status:>7s}] {tag}"]
        if email:
            parts.append(f"    邮箱: {email}")
        if token_file:
            parts.append(f"    文件: {token_file}")
        print("\n".join(parts))
    print("-" * 60)


def collect_success_files(rows: list[dict[str, Any]], run_id: str) -> str:
    """
    将所有注册成功（status=ok）的 token 文件拷贝到 data/<run_id>/ 文件夹中。
    返回目标文件夹路径。
    """
    dest_dir = os.path.join(os.getcwd(), "data", run_id)
    os.makedirs(dest_dir, exist_ok=True)

    copied = 0
    for r in rows:
        if r.get("status") != "ok":
            continue
        token_file = r.get("token_file", "")
        if not token_file or not os.path.isfile(token_file):
            log(f"任务 {r.get('id')} 状态为 ok 但 token 文件不存在: {token_file}")
            continue
        dest_path = os.path.join(dest_dir, os.path.basename(token_file))
        shutil.copy2(token_file, dest_path)
        copied += 1

    log(f"已将 {copied} 个成功的 token 文件拷贝到: {dest_dir}")
    return dest_dir


def main() -> None:
    global _log_file_path

    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--python", default="python3")
    parser.add_argument(
        "--script",
        default=os.path.join(os.getcwd(), "kiro_full_flow_cn.py"),
    )
    parser.add_argument("--run-id", default="batch")
    args = parser.parse_args()

    if args.count < 1:
        raise SystemExit("--count 必须 >= 1")
    if args.workers < 1:
        raise SystemExit("--workers 必须 >= 1")

    run_id = normalize_run_id(args.run_id)
    env = os.environ.copy()
    lock = threading.Lock()

    # 创建data目录和log文件
    data_dir = os.path.join(os.getcwd(), "data")
    os.makedirs(data_dir, exist_ok=True)
    log_filename = datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"
    _log_file_path = os.path.join(data_dir, log_filename)

    log(f"批量注册开始: count={args.count}, workers={args.workers}, run-id={run_id}")
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
            rows.append(fut.result())

    elapsed = time.time() - start_time
    print_table(rows)

    ok_count = sum(1 for r in rows if r.get("status") == "ok")
    if ok_count > 0:
        dest_dir = collect_success_files(rows, run_id)
        log(f"成功文件夹: {dest_dir}")
    else:
        log("没有注册成功的账号，跳过文件归集")

    log(f"总耗时: {elapsed:.1f} 秒")


if __name__ == "__main__":
    main()
