#!/usr/bin/env python3
"""
批量并发执行 kiro_full_flow_cn.py，并汇总注册结果。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

import requests

# ANSI 颜色代码
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

# 状态图标（emoji）
STATUS_ICONS = {
    "ok": "✅",
    "blocked": "❌",
    "ban": "⛔",
    "failed": "❌",
    "unknown": "❓",
    "running": "⏳",
}

# 全局状态
class GlobalState:
    def __init__(self):
        self.lock = threading.Lock()
        self.log_dir: str | None = None
        self.task_log_dir: str | None = None
        self.total_tasks = 0
        self.completed = 0
        self.results: list[dict[str, Any]] = []
        self.running_tasks: set[str] = set()
        # 计数
        self.ok_count = 0
        self.ban_count = 0
        self.blocked_count = 0
        self.failed_count = 0
        self.unknown_count = 0
        # 停止标志和子进程跟踪
        self.stop_event = threading.Event()
        self.processes: dict[str, subprocess.Popen] = {}

    def should_stop(self) -> bool:
        return self.stop_event.is_set()

    def request_stop(self):
        self.stop_event.set()
        self._kill_all_processes()

    def register_process(self, task_id: str, proc: subprocess.Popen):
        with self.lock:
            self.processes[task_id] = proc

    def unregister_process(self, task_id: str):
        with self.lock:
            self.processes.pop(task_id, None)

    def _kill_all_processes(self):
        """终止所有子进程"""
        with self.lock:
            processes = dict(self.processes)
        for task_id, proc in processes.items():
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def add_running(self, task_id: str):
        with self.lock:
            self.running_tasks.add(task_id)
            self._update_progress()

    def remove_running(self, task_id: str):
        with self.lock:
            self.running_tasks.discard(task_id)

    def add_result(self, result: dict[str, Any]):
        with self.lock:
            self.results.append(result)
            self.completed += 1
            status = result.get("status", "unknown")
            if status == "ok":
                self.ok_count += 1
            elif status == "ban":
                self.ban_count += 1
            elif status == "blocked":
                self.blocked_count += 1
            elif status == "failed":
                self.failed_count += 1
            else:
                self.unknown_count += 1
            self._update_progress()

    def _update_progress(self):
        """更新进度条显示"""
        # 清除当前行并移动到行首
        sys.stdout.write("\r\033[K")
        # 构建进度信息
        progress = f"{Colors.BOLD}[{self.completed}/{self.total_tasks}]{Colors.RESET}"
        counts = (
            f"✅{self.ok_count} "
            f"⛔{self.ban_count} "
            f"❌{self.blocked_count} "
            f"❌{self.failed_count}"
        )
        # 显示正在运行的任务
        running_str = ""
        if self.running_tasks:
            running_list = sorted(self.running_tasks)[:4]  # 最多显示4个
            running_str = f" | ⏳ {', '.join(running_list)}"
            if len(self.running_tasks) > 4:
                running_str += f" +{len(self.running_tasks) - 4}"
        sys.stdout.write(f"{progress} {counts}{running_str}")
        sys.stdout.flush()

    def finish_progress(self):
        """完成进度显示，换行"""
        sys.stdout.write("\n")
        sys.stdout.flush()


_state = GlobalState()

# 发卡平台配置
_faka_url: str | None = None
_faka_username: str | None = None
_faka_password: str | None = None
_faka_session: requests.Session | None = None
_faka_lock = threading.Lock()


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def log_to_file(msg: str, task_id: str | None = None) -> None:
    """写入日志文件"""
    if not _state.log_dir:
        return
    log_line = f"[{now_str()}] {msg}"
    # 写入主日志
    main_log = os.path.join(_state.log_dir, "main.log")
    with open(main_log, "a", encoding="utf-8") as f:
        f.write(log_line + "\n")
    # 如果指定了任务ID，写入任务日志
    if task_id and _state.task_log_dir:
        task_log = os.path.join(_state.task_log_dir, f"{task_id}.log")
        with open(task_log, "a", encoding="utf-8") as f:
            f.write(log_line + "\n")


def log(msg: str, task_id: str | None = None) -> None:
    """打印日志（仅在非进度模式下）"""
    log_to_file(msg, task_id)


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
    with _faka_lock:
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


def upload_to_faka(result_file: str, task_id: str) -> bool:
    """上传账号到发卡平台"""
    session = faka_login()
    if not session:
        return False

    try:
        with open(result_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log(f"读取结果文件失败: {e}", task_id)
        return False

    token_output = data.get("token_output", {})
    if not isinstance(token_output, dict):
        token_output = {}

    email = token_output.get("email") or data.get("email")
    if not email:
        log(f"结果文件中未找到邮箱: {result_file}", task_id)
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
                log(f"上传发卡平台成功: {email}", task_id)
                return True
            else:
                failed = result.get("failed", [])
                if failed:
                    log(f"上传发卡平台失败: {failed[0].get('error', '未知错误')}", task_id)
                return False
        else:
            log(f"上传发卡平台失败: {result.get('error', '未知错误')}", task_id)
            return False
    except Exception as e:
        log(f"上传发卡平台异常: {e}", task_id)
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
) -> dict[str, Any]:
    tag = f"{run_id}-{idx}"

    # 检查是否已请求停止
    if _state.should_stop():
        log("收到停止信号，跳过任务", tag)
        return {"id": tag, "status": "failed", "error": "cancelled"}

    log(f"开始任务 {tag}", tag)
    _state.add_running(tag)

    job_env = dict(env)
    job_env["KIRO_RUN_ID"] = tag

    proc = None
    try:
        # 使用 Popen 以便能够终止子进程
        proc = subprocess.Popen(
            [python_exe, script_path],
            env=job_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _state.register_process(tag, proc)

        # 等待进程完成，同时检查停止信号
        while proc.poll() is None:
            if _state.should_stop():
                log("收到停止信号，终止任务", tag)
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                return {"id": tag, "status": "failed", "error": "cancelled"}
            time.sleep(0.1)

        # 获取子进程输出
        stdout, stderr = proc.communicate()
        output = "".join([stdout or "", stderr or ""])

        # 将子进程输出写入任务日志文件
        if _state.task_log_dir and output:
            task_log = os.path.join(_state.task_log_dir, f"{tag}.log")
            with open(task_log, "a", encoding="utf-8") as f:
                f.write(f"\n{'=' * 40}\n")
                f.write(f"子进程输出:\n")
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
            log(f"完成: status={status}, email={email}", tag)

            # 上传到发卡平台（仅成功时）
            faka_uploaded = False
            if status == "ok" and _faka_url:
                faka_uploaded = upload_to_faka(result_file, tag)

            return {
                "id": tag,
                "status": status,
                "result_file": result_file,
                "token_file": token_file,
                "email": email,
                "faka_uploaded": faka_uploaded,
            }

        log(f"未找到结果文件，标记为 failed", tag)
        return {"id": tag, "status": "failed"}

    except Exception as e:
        log(f"执行异常: {e}", tag)
        return {"id": tag, "status": "failed", "error": str(e)}
    finally:
        _state.unregister_process(tag)
        _state.remove_running(tag)


def print_summary(rows: list[dict[str, Any]], elapsed: float) -> None:
    """打印最终汇总"""
    total = len(rows)
    ok = sum(1 for r in rows if r.get("status") == "ok")
    blocked = sum(1 for r in rows if r.get("status") == "blocked")
    ban = sum(1 for r in rows if r.get("status") == "ban")
    failed = sum(1 for r in rows if r.get("status") == "failed")
    unknown = sum(1 for r in rows if r.get("status") == "unknown")

    print()
    print(f"{Colors.BOLD}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}📊 结果汇总{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 60}{Colors.RESET}")
    print(f"总数: {total} | ✅{ok} | ⛔{ban} | ❌{blocked} | ❓{unknown}")
    print(f"⏱️ 总耗时: {elapsed:.1f} 秒")
    print()

    # 详细列表
    print(f"{Colors.BOLD}📋 详细列表：{Colors.RESET}")
    print("-" * 60)
    sorted_rows = sorted(rows, key=lambda r: r.get("id", ""))
    for r in sorted_rows:
        status = r.get("status", "unknown")
        tag = r.get("id", "?")
        email = r.get("email", "")
        faka_uploaded = r.get("faka_uploaded", False)
        icon = STATUS_ICONS.get(status, "❓")
        line = f"  {icon} {tag}"
        if email:
            line += f" | {email}"
        if status == "ok" and _faka_url:
            upload_icon = "📤" if faka_uploaded else "❌"
            line += f" | {upload_icon}"
        print(line)
    print("-" * 60)

    if ok > 0:
        print(f"\n✅ 成功账号 token 文件已保存在 data/ok/ 目录")


def main() -> None:
    global _faka_url, _faka_username, _faka_password

    parser = argparse.ArgumentParser(description="批量注册 Kiro 账号")
    parser.add_argument("--count", type=int, default=1, help="注册数量")
    parser.add_argument("--workers", type=int, default=1, help="并发数")
    parser.add_argument("--python", default="python3", help="Python 解释器路径")
    parser.add_argument(
        "--script",
        default=os.path.join(os.getcwd(), "kiro_full_flow_cn.py"),
        help="注册脚本路径",
    )
    parser.add_argument("--run-id", default="batch", help="运行ID，用于日志目录名")
    parser.add_argument("--faka-url", help="发卡平台地址")
    parser.add_argument("--faka-username", help="发卡平台管理员用户名")
    parser.add_argument("--faka-password", help="发卡平台管理员密码")
    args = parser.parse_args()

    if args.count < 1:
        raise SystemExit("--count 必须 >= 1")
    if args.workers < 1:
        raise SystemExit("--workers 必须 >= 1")

    run_id = normalize_run_id(args.run_id)
    env = os.environ.copy()

    # 设置发卡平台配置
    _faka_url = args.faka_url
    _faka_username = args.faka_username
    _faka_password = args.faka_password

    # 注册信号处理器
    def signal_handler(signum, frame):
        print(f"\n\n⚠️ 收到终止信号，正在停止所有任务...")
        _state.request_stop()
        # 只处理一次信号
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # 创建日志目录结构：log/<run_id>/
    log_base = os.path.join(os.getcwd(), "log")
    os.makedirs(log_base, exist_ok=True)
    _state.log_dir = os.path.join(log_base, run_id)
    os.makedirs(_state.log_dir, exist_ok=True)
    _state.task_log_dir = os.path.join(_state.log_dir, "tasks")
    os.makedirs(_state.task_log_dir, exist_ok=True)

    # 创建 data/ok 目录
    data_ok_dir = os.path.join(os.getcwd(), "data", "ok")
    os.makedirs(data_ok_dir, exist_ok=True)

    _state.total_tasks = args.count

    # 打印启动信息
    print(f"{Colors.BOLD}批量注册开始{Colors.RESET}")
    print(f"  数量: {args.count}")
    print(f"  并发: {args.workers}")
    print(f"  运行ID: {run_id}")
    print(f"  日志目录: {_state.log_dir}")
    if _faka_url:
        print(f"  发卡平台: {_faka_url}")
    print()

    log(f"批量注册开始: count={args.count}, workers={args.workers}, run-id={run_id}")
    start_time = time.time()

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = []
            for idx in range(args.count):
                # 检查停止信号
                if _state.should_stop():
                    break
                futures.append(
                    executor.submit(
                        run_one,
                        run_id,
                        idx + 1,
                        args.count,
                        args.python,
                        args.script,
                        env,
                    )
                )
                if idx < args.count - 1:
                    time.sleep(1)

            for fut in as_completed(futures):
                try:
                    result = fut.result()
                    _state.add_result(result)
                except Exception as e:
                    log(f"获取任务结果异常: {e}")
                    _state.add_result({"id": "unknown", "status": "failed", "error": str(e)})
    except KeyboardInterrupt:
        print(f"\n⚠️ 用户中断，正在退出...")

    _state.finish_progress()
    elapsed = time.time() - start_time
    print_summary(_state.results, elapsed)

    # 写入最终汇总到日志
    log(f"批量注册完成: 总耗时 {elapsed:.1f} 秒")


if __name__ == "__main__":
    main()
