#!/usr/bin/env python3
"""
Kiro 登录两阶段完整脚本（中文日志版）

本脚本覆盖的流程：
1) 生成第一阶段参数：state + PKCE(code_verifier/code_challenge)
2) 调用 Kiro Portal 的 InitiateLogin（CBOR RPC）
3) 处理第一层本地回调（/ 或 /signin/callback）
4) 调用 AWS OIDC 动态注册客户端（/client/register）
5) 构造并打开 AWS OIDC 授权页（/authorize）
6) 接收第二层本地回调（/oauth/callback）拿到 authorization code
7) （默认）调用 AWS OIDC /token 用 code + code_verifier 换 token
8) 校验 token 返回字段，并保存完整结果到文件

注意：
- 该脚本用于研究与调试登录链路，请仅在你有权限的环境中使用。
- 第二阶段需要你在浏览器完成真实登录操作。
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import random
import re
import socket
import string
import subprocess
import threading
import time
import uuid
import webbrowser
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import cbor2
import requests


CONFIG_PATH_ENV = "KIRO_FULL_FLOW_CONFIG"
RUN_ID_ENV = "KIRO_RUN_ID"
DEFAULT_CONFIG_PATH = os.path.join(os.getcwd(), "config", "kiro_full_flow_cn.json")


@dataclass(frozen=True)
class FlowConfig:
    portal_url: str
    idp: str
    start_url: str
    idc_region: str
    redirect_from: str
    register_redirect_uri: str
    timeout_s: int
    open_browser: bool
    exchange_token: bool
    verify_credential: bool
    profile_arn: str
    browser: str
    camoufox_headless: bool
    camoufox_os: str
    camoufox_startup_timeout_s: Optional[int]
    camoufox_autofill_email: bool
    save_result: bool
    output_json: bool
    callback_port: Optional[int]


@dataclass(frozen=True)
class ShortmailConfig:
    base_url: str
    origin: str
    bootstrap_token: str
    domain: str
    fingerprint: str
    user_agent: str


@dataclass(frozen=True)
class TokenOutputConfig:
    auth_region: str
    api_region: str


@dataclass(frozen=True)
class AppConfig:
    flow: FlowConfig
    callback_ports: list[int]
    initiate_login_path: str
    kiro_grant_scopes: list[str]
    fixed_profile_arns: dict[str, str]
    password_symbols: str
    shortmail: ShortmailConfig
    token_output: TokenOutputConfig


def _require_key(container: dict[str, Any], key: str, expected_type: type) -> Any:
    if key not in container:
        raise RuntimeError(f"配置缺少必填项: {key}")
    value = container[key]
    if not isinstance(value, expected_type):
        raise RuntimeError(f"配置项类型错误: {key}，期望 {expected_type.__name__}")
    return value


def load_app_config() -> AppConfig:
    config_path = os.environ.get(CONFIG_PATH_ENV, DEFAULT_CONFIG_PATH)
    if not os.path.exists(config_path):
        raise RuntimeError(
            f"配置文件不存在: {config_path}。请创建该文件，或设置环境变量 {CONFIG_PATH_ENV} 指向配置文件。"
        )

    with open(config_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, dict):
        raise RuntimeError(f"配置文件格式错误: {config_path} 顶层必须是 JSON 对象")

    flow_raw = _require_key(raw, "flow", dict)
    shortmail_raw = _require_key(raw, "shortmail", dict)
    token_output_raw = _require_key(raw, "tokenOutput", dict)

    flow = FlowConfig(
        portal_url=str(_require_key(flow_raw, "portalUrl", str)),
        idp=str(_require_key(flow_raw, "idp", str)),
        start_url=str(_require_key(flow_raw, "startUrl", str)),
        idc_region=str(_require_key(flow_raw, "idcRegion", str)),
        redirect_from=str(_require_key(flow_raw, "redirectFrom", str)),
        register_redirect_uri=str(_require_key(flow_raw, "registerRedirectUri", str)),
        timeout_s=int(_require_key(flow_raw, "timeoutSeconds", int)),
        open_browser=bool(_require_key(flow_raw, "openBrowser", bool)),
        exchange_token=bool(_require_key(flow_raw, "exchangeToken", bool)),
        verify_credential=bool(_require_key(flow_raw, "verifyCredential", bool)),
        profile_arn=str(_require_key(flow_raw, "profileArn", str)),
        browser=str(_require_key(flow_raw, "browser", str)),
        camoufox_headless=bool(_require_key(flow_raw, "camoufoxHeadless", bool)),
        camoufox_os=str(_require_key(flow_raw, "camoufoxOs", str)),
        camoufox_startup_timeout_s=(
            int(flow_raw["camoufoxStartupTimeoutSeconds"])
            if flow_raw.get("camoufoxStartupTimeoutSeconds") is not None
            else None
        ),
        camoufox_autofill_email=bool(
            _require_key(flow_raw, "camoufoxAutofillEmail", bool)
        ),
        save_result=bool(_require_key(flow_raw, "saveResult", bool)),
        output_json=bool(_require_key(flow_raw, "outputJson", bool)),
        callback_port=(
            int(flow_raw["callbackPort"])
            if flow_raw.get("callbackPort") is not None
            else None
        ),
    )

    callback_ports_raw = _require_key(raw, "callbackPorts", list)
    callback_ports: list[int] = [int(p) for p in callback_ports_raw]
    if not callback_ports:
        raise RuntimeError("配置项 callbackPorts 不能为空")

    kiro_grant_scopes_raw = _require_key(raw, "kiroGrantScopes", list)
    kiro_grant_scopes: list[str] = [
        str(s) for s in kiro_grant_scopes_raw if str(s).strip()
    ]
    if not kiro_grant_scopes:
        raise RuntimeError("配置项 kiroGrantScopes 不能为空")

    fixed_profile_arns_raw = _require_key(raw, "fixedProfileArns", dict)
    fixed_profile_arns: dict[str, str] = {
        str(k).lower(): str(v) for k, v in fixed_profile_arns_raw.items()
    }

    shortmail = ShortmailConfig(
        base_url=str(_require_key(shortmail_raw, "baseUrl", str)),
        origin=str(_require_key(shortmail_raw, "origin", str)),
        bootstrap_token=str(_require_key(shortmail_raw, "bootstrapToken", str)),
        domain=str(_require_key(shortmail_raw, "domain", str)),
        fingerprint=str(_require_key(shortmail_raw, "fingerprint", str)),
        user_agent=str(_require_key(shortmail_raw, "userAgent", str)),
    )

    token_output = TokenOutputConfig(
        auth_region=str(_require_key(token_output_raw, "authRegion", str)),
        api_region=str(_require_key(token_output_raw, "apiRegion", str)),
    )

    return AppConfig(
        flow=flow,
        callback_ports=callback_ports,
        initiate_login_path=str(_require_key(raw, "initiateLoginPath", str)),
        kiro_grant_scopes=kiro_grant_scopes,
        fixed_profile_arns=fixed_profile_arns,
        password_symbols=str(_require_key(raw, "passwordSymbols", str)),
        shortmail=shortmail,
        token_output=token_output,
    )


APP_CONFIG = load_app_config()
FLOW_CONFIG = APP_CONFIG.flow


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def log(msg: str) -> None:
    print(f"[{now_str()}] {msg}")


def b64url_no_padding(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode_no_padding(raw: str) -> bytes:
    padded = raw + "=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def generate_code_verifier() -> str:
    # Kiro: crypto.randomBytes(32).toString("base64url")
    return b64url_no_padding(os.urandom(32))


def generate_code_challenge(code_verifier: str) -> str:
    # Kiro: sha256(code_verifier).base64url
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return b64url_no_padding(digest)


def first_available_port(candidates: list[int]) -> int:
    for port in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(
        "候选端口均不可用，请在 FLOW_CONFIG.callback_port 中指定可用端口"
    )


def ensure_available_port(candidates: list[int], retries: int = 3) -> int:
    last_err: Optional[Exception] = None
    for _ in range(max(1, retries)):
        try:
            return first_available_port(candidates)
        except Exception as e:
            last_err = e
            time.sleep(0.4)
    raise RuntimeError(f"候选端口均不可用（重试 {retries} 次）：{last_err}")


def build_portal_signin_url(
    portal_url: str,
    state: str,
    code_challenge: str,
    redirect_uri: str,
    redirect_from: str,
    from_amazon_internal: bool = False,
) -> str:
    params: list[tuple[str, str]] = [
        ("state", state),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("redirect_uri", redirect_uri),
        ("redirect_from", redirect_from),
    ]
    if from_amazon_internal:
        params.append(("from_amazon_internal", "true"))
    return f"{portal_url.rstrip('/')}/signin?{urlencode(params)}"


def make_visitor_id() -> str:
    return f"{int(time.time())}-{uuid.uuid4().hex[:8]}"


def mask_secret(value: str, head: int = 16, tail: int = 8) -> str:
    if len(value) <= head + tail + 3:
        return value
    return f"{value[:head]}...{value[-tail:]}"


def _shortmail_headers(token: Optional[str] = None) -> dict[str, str]:
    shortmail = APP_CONFIG.shortmail
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9",
        "cache-control": "no-cache",
        "origin": shortmail.origin,
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": f"{shortmail.origin}/",
        "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": shortmail.user_agent,
        "x-admin-auth": "",
        "x-custom-auth": "",
        "x-fingerprint": shortmail.fingerprint,
        "x-lang": "zh",
        "x-user-token": "",
        "content-type": "application/json",
    }
    if token:
        headers["authorization"] = f"Bearer {token}"
    return headers


def create_short_email(
    username: Optional[str] = None,
    max_retries: int = 5,
    retry_sleep_s: float = 2.5,
) -> tuple[str, str, str]:
    """
    创建短效邮箱，返回 (email, jwt, password)。
    适配 DuckMail: POST /accounts + POST /token

    如果传入 username，则使用该用户名；否则随机生成 10 位用户名。
    """
    shortmail = APP_CONFIG.shortmail
    last_err: Optional[Exception] = None
    for _ in range(max_retries):
        try:
            if username is None:
                _uname = "".join(
                    random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=10)
                )
            else:
                _uname = username
            email = f"{_uname}@{shortmail.domain}"
            password = generate_strong_password()

            resp = requests.post(
                f"{shortmail.base_url}/accounts",
                json={"address": email, "password": password},
                headers=_shortmail_headers(shortmail.bootstrap_token),
                timeout=30,
            )
            if resp.status_code == 409:
                raise RuntimeError("邮箱地址已存在")
            resp.raise_for_status()

            token_resp = requests.post(
                f"{shortmail.base_url}/token",
                json={"address": email, "password": password},
                headers=_shortmail_headers(),
                timeout=30,
            )
            token_resp.raise_for_status()
            token_data = token_resp.json()
            jwt = str(token_data.get("token", "") or "")
            if not jwt:
                raise RuntimeError("短效邮箱接口返回缺少 token")
            return email, jwt, password
        except Exception as e:
            last_err = e
            time.sleep(retry_sleep_s)
    raise RuntimeError(f"短效邮箱创建失败（已重试 {max_retries} 次）：{last_err}")


def _duckmail_message_raw(detail: dict[str, Any]) -> str:
    text = str(detail.get("text", "") or "")
    html = detail.get("html")
    if isinstance(html, list):
        html_text = " ".join([str(item or "") for item in html])
    else:
        html_text = str(html or "")
    return " ".join([text, html_text]).strip()


def fetch_shortmail_mails(jwt: str, limit: int = 20, offset: int = 0) -> dict[str, Any]:
    """
    获取短效邮箱邮件列表。
    适配 DuckMail: GET /messages + GET /messages/{id}
    """
    shortmail = APP_CONFIG.shortmail
    resp = requests.get(
        f"{shortmail.base_url}/messages",
        params={"page": max(1, int(offset / max(1, limit)) + 1)},
        headers=_shortmail_headers(jwt),
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        return {"raw": data}

    members = data.get("hydra:member")
    if isinstance(members, list) and members:
        first = members[0]
        msg_id = str(first.get("id", "") or "")
        if msg_id:
            msg_resp = requests.get(
                f"{shortmail.base_url}/messages/{msg_id}",
                headers=_shortmail_headers(jwt),
                timeout=30,
            )
            msg_resp.raise_for_status()
            detail = msg_resp.json()
            raw = _duckmail_message_raw(detail) if isinstance(detail, dict) else ""
            return {
                "results": [
                    {
                        "id": msg_id,
                        "raw": raw,
                        "detail": detail,
                    }
                ]
            }
    return data


def wait_for_shortmail_first_mail_json(
    jwt: str,
    max_wait_s: int = 330,
    poll_interval_s: float = 3.0,
) -> dict[str, Any]:
    """
    轮询短效邮箱，直到拿到至少一封邮件并返回原始 JSON。
    """
    deadline = time.time() + max_wait_s
    last_err: Optional[Exception] = None
    while time.time() < deadline:
        try:
            data = fetch_shortmail_mails(jwt=jwt, limit=20, offset=0)
            results = data.get("results")
            if isinstance(results, list) and len(results) > 0:
                return data
        except Exception as e:
            last_err = e
        time.sleep(poll_interval_s)
    if last_err is not None:
        raise RuntimeError(
            f"轮询邮箱超时（{max_wait_s} 秒），最后一次请求异常：{last_err}"
        )
    raise RuntimeError(f"轮询邮箱超时（{max_wait_s} 秒），未获取到任何邮件")


def extract_verification_code_from_shortmail_json(
    mail_json: dict[str, Any],
) -> Optional[str]:
    """
    从短效邮箱返回 JSON 中提取 6 位验证码。
    当前优先匹配 AWS Builder ID 邮件中的固定文案：
    - Verification code:: 123456
    - Verification code: 123456
    """
    results = mail_json.get("results")
    if not isinstance(results, list) or not results:
        return None

    # 尽量优先最新一封（id 更大通常更新）
    normalized_results: list[dict[str, Any]] = []
    for item in results:
        if isinstance(item, dict):
            normalized_results.append(item)

    def _safe_sort_key(item: dict[str, Any]) -> tuple[int, str]:
        raw_id = str(item.get("id", "") or "")
        try:
            return int(raw_id), raw_id
        except Exception:
            return 0, raw_id

    normalized_results.sort(key=_safe_sort_key, reverse=True)

    patterns = [
        re.compile(r"Verification\s+code\s*[:：]+\s*([0-9]{6})", re.IGNORECASE),
        re.compile(r"code\"[^>]*>\s*([0-9]{6})\s*<", re.IGNORECASE),
    ]

    for item in normalized_results:
        raw = str(item.get("raw", "") or "")
        if not raw:
            continue
        for p in patterns:
            m = p.search(raw)
            if m:
                return m.group(1)
    return None


def generate_random_english_name() -> str:
    """
    生成仅由英文字母组成的随机英文全名（First Last）。
    """
    first_len = random.randint(4, 8)
    last_len = random.randint(5, 10)
    first = "".join(random.choices(string.ascii_lowercase, k=first_len)).capitalize()
    last = "".join(random.choices(string.ascii_lowercase, k=last_len)).capitalize()
    return f"{first} {last}"


_NAME_POOL: Optional[list[tuple[str, str]]] = None


def load_name_pool() -> list[tuple[str, str]]:
    """
    从 config/name.txt 加载姓名库，返回 [(first_name, last_name), ...]。
    跳过空行和只有 first name 没有 last name 的行。
    """
    global _NAME_POOL
    if _NAME_POOL is not None:
        return _NAME_POOL

    name_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "name.txt")
    if not os.path.isfile(name_file):
        log(f"姓名库文件不存在：{name_file}，将使用随机生成")
        _NAME_POOL = []
        return _NAME_POOL

    pool: list[tuple[str, str]] = []
    with open(name_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) < 2:
                # 跳过只有 first name 的行（如 "Felix"）
                continue
            first_name, last_name = parts[0], parts[1]
            pool.append((first_name, last_name))

    _NAME_POOL = pool
    log(f"姓名库已加载：共 {len(pool)} 条记录")
    return _NAME_POOL


def _sanitize_for_email(name: str) -> str:
    """
    将姓名中的特殊字符移除，只保留英文字母，并转为小写。
    例如："O'Connor" -> "oconnor"，"Lou(ie)" -> "louie"，"Burne-Jones" -> "burnejones"
    """
    return re.sub(r"[^a-zA-Z]", "", name).lower()


def pick_name_from_pool() -> tuple[str, str]:
    """
    从姓名库随机选取一条记录，返回 (full_name, email_username)。
    - full_name: 原始全名，如 "Jacob Harrod"
    - email_username: lastnameNN 格式，如 "harrod42"

    如果姓名库为空或不可用，则回退到 generate_random_english_name()。
    """
    pool = load_name_pool()
    if not pool:
        fallback_name = generate_random_english_name()
        parts = fallback_name.split()
        last = parts[-1] if len(parts) > 1 else parts[0]
        nn = random.randint(1, 99)
        return fallback_name, f"{last.lower()}{nn:02d}"

    first_name, last_name = random.choice(pool)
    full_name = f"{first_name} {last_name}"
    sanitized_last = _sanitize_for_email(last_name)
    if not sanitized_last:
        sanitized_last = _sanitize_for_email(first_name)
    if not sanitized_last:
        sanitized_last = "user"
    nn = random.randint(1, 99)
    email_username = f"{sanitized_last}{nn:02d}"
    return full_name, email_username


def generate_strong_password(length: int = 12) -> str:
    """
    生成满足 Builder ID 密码策略的随机密码：
    - 8-64 位
    - 包含大小写字母、数字、符号
    """
    if length < 8:
        length = 8
    if length > 64:
        length = 64

    uppers = string.ascii_uppercase
    lowers = string.ascii_lowercase
    digits = string.digits
    symbols = APP_CONFIG.password_symbols

    required = [
        random.choice(uppers),
        random.choice(lowers),
        random.choice(digits),
        random.choice(symbols),
    ]
    pool = uppers + lowers + digits + symbols
    remaining = [random.choice(pool) for _ in range(length - len(required))]
    chars = required + remaining
    random.shuffle(chars)
    return "".join(chars)


def decode_jwt_payload_no_verify(token: str) -> dict[str, Any]:
    """
    仅用于调试可视化，不做签名校验。
    """
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        payload_bytes = b64url_decode_no_padding(parts[1])
        payload = json.loads(payload_bytes.decode("utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def validate_token_response(token_resp: dict[str, Any]) -> dict[str, Any]:
    access_token = str(token_resp.get("accessToken", "") or "")
    refresh_token = str(token_resp.get("refreshToken", "") or "")
    token_type = str(token_resp.get("tokenType", "") or "")

    expires_in_raw = token_resp.get("expiresIn")
    expires_in: Optional[int]
    try:
        expires_in = int(expires_in_raw) if expires_in_raw is not None else None
    except (TypeError, ValueError):
        expires_in = None

    id_token = str(token_resp.get("idToken", "") or "")
    access_payload = decode_jwt_payload_no_verify(access_token) if access_token else {}
    id_payload = decode_jwt_payload_no_verify(id_token) if id_token else {}

    return {
        "has_access_token": bool(access_token),
        "has_refresh_token": bool(refresh_token),
        "has_token_type": bool(token_type),
        "token_type": token_type or None,
        "expires_in": expires_in,
        "expires_in_valid": expires_in is not None and expires_in > 0,
        "has_id_token": bool(id_token),
        "access_token_preview": mask_secret(access_token) if access_token else None,
        "refresh_token_preview": mask_secret(refresh_token) if refresh_token else None,
        "id_token_preview": mask_secret(id_token) if id_token else None,
        "access_token_payload_no_verify": access_payload,
        "id_token_payload_no_verify": id_payload,
        "is_minimally_usable": bool(access_token)
        and bool(refresh_token)
        and (expires_in is not None and expires_in > 0),
    }


def normalize_email_for_filename(email: str) -> str:
    base = email.strip().lower()
    base = base.replace("@", "-")
    base = base.replace(".", "-")
    base = re.sub(r"[^a-z0-9+_-]", "-", base)
    base = re.sub(r"-+", "-", base).strip("-")
    return base or "unknown"


def normalize_filename_fragment(value: str) -> str:
    base = value.strip()
    base = re.sub(r"[^a-zA-Z0-9._-]", "-", base)
    base = re.sub(r"-+", "-", base).strip("-")
    return base or ""


def get_run_id() -> Optional[str]:
    raw = os.environ.get(RUN_ID_ENV, "").strip()
    if not raw:
        return None
    safe = normalize_filename_fragment(raw)
    return safe or None


def build_default_token_file(email: Optional[str] = None) -> str:
    data_dir = os.path.join(os.getcwd(), "data")
    os.makedirs(data_dir, exist_ok=True)
    if email:
        safe_email = normalize_email_for_filename(email)
        filename = f"kiro-builder-id-{safe_email}.json"
    else:
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        filename = f"kiro_refresh_token_bundle_{ts}.json"
    run_id = get_run_id()
    if run_id:
        name, ext = os.path.splitext(filename)
        filename = f"{name}__{run_id}{ext}"
    return os.path.join(data_dir, filename)


def build_mail_output_file(token_file: str) -> str:
    base, ext = os.path.splitext(token_file)
    if not ext:
        ext = ".json"
    return f"{base}_mail{ext}"


def build_result_output_file(token_file: str) -> str:
    base, ext = os.path.splitext(token_file)
    if not ext:
        ext = ".json"
    return f"{base}_result{ext}"


def save_json_file(path: str, data: Any) -> None:
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def build_refresh_token_bundle(
    refresh_token: str,
    access_token: str,
    client_id: str,
    client_secret: str,
    region: str,
    email: str = "",
    profile_arn: str = "",
    start_url: str = "https://view.awsapps.com/start",
) -> dict[str, Any]:
    now = time.localtime()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S", now)
    # 计算本地 UTC 偏移，格式如 +08:00
    utc_offset = time.strftime("%z", now)
    if len(utc_offset) == 5:  # e.g. "+0800"
        utc_offset = utc_offset[:3] + ":" + utc_offset[3:]
    now_iso += utc_offset
    # expires_at = 当前时间 + 1 小时
    expires_ts = time.mktime(now) + 3600
    expires_local = time.localtime(expires_ts)
    expires_iso = time.strftime("%Y-%m-%dT%H:%M:%S", expires_local)
    expires_iso += utc_offset

    return {
        "access_token": access_token,
        "auth_method": "builder-id",
        "client_id": client_id,
        "client_secret": client_secret,
        "disabled": False,
        "email": email,
        "expires_at": expires_iso,
        "last_refresh": now_iso,
        "profile_arn": profile_arn,
        "provider": "AWS",
        "refresh_token": refresh_token,
        "region": region,
        "start_url": start_url,
        "type": "kiro",
    }


class CamoufoxSession:
    """
    在后台线程中托管 AsyncCamoufox 生命周期，便于主流程继续等待本地回调。
    """

    def __init__(self, url: str, headless: bool, os_name: str, auto_fill_email: bool):
        self.url = url
        self.headless = headless
        self.os_name = os_name
        self.auto_fill_email = auto_fill_email
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.ready_event = threading.Event()
        self.started_ok = False
        self.detail = ""
        self.error = ""
        self.temp_email: Optional[str] = None
        self.temp_email_jwt: Optional[str] = None
        self.temp_email_password: Optional[str] = None
        self.shortmail_first_mail_json: Optional[dict[str, Any]] = None
        self.shortmail_poll_error: Optional[str] = None
        self.extracted_verification_code: Optional[str] = None
        self.verification_code_submitted = False
        self.generated_password: Optional[str] = None
        self.password_submitted = False
        self.allow_access_clicked = False
        self.generated_full_name: Optional[str] = None
        self.fill_submitted = False
        self.name_fill_submitted = False
        self.autofill_error: Optional[str] = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._thread_entry, daemon=True)
        self.thread.start()

    def _trace(self, msg: str) -> None:
        log(f"[Camoufox] {msg}")

    def _thread_entry(self) -> None:
        try:
            self._trace("后台线程启动")
            asyncio.run(self._run())
        except Exception as e:
            self.error = f"Camoufox 线程异常: {e}"
            self._trace(self.error)
            self.ready_event.set()

    async def _run(self) -> None:
        try:
            from camoufox.async_api import AsyncCamoufox
        except Exception as e:
            self.error = (
                f"无法导入 camoufox：{e}。请在当前 Python 环境安装 camoufox 后重试。"
            )
            self._trace(self.error)
            self.ready_event.set()
            return

        selected_os = self.os_name
        if selected_os == "auto":
            selected_os = random.choice(["windows", "macos", "linux"])

        camoufox_obj = None
        context = None
        try:
            self._trace(f"准备启动浏览器: headless={self.headless}, os={selected_os}")
            camoufox_obj = AsyncCamoufox(
                headless=self.headless,
                os=selected_os,
                locale="en-US",
                humanize=False,
                geoip=False,
                i_know_what_im_doing=True,
                block_webrtc=True,
                disable_coop=True,
            )
            browser = await camoufox_obj.__aenter__()
            context = await browser.new_context()
            page = await context.new_page()
            page.set_default_timeout(0)
            page.set_default_navigation_timeout(0)
            self._trace("浏览器上下文创建成功，准备打开授权页")
            await page.goto(self.url, wait_until="domcontentloaded", timeout=0)
            self._trace(f"已打开授权页: {self.url}")

            if self.auto_fill_email:
                try:
                    self._trace("开始自动填充流程：邮箱 -> Continue -> (可选)姓名")
                    # 等待页面 DOM 完整加载，避免按钮尚未可交互时过早点击。
                    await page.wait_for_function(
                        "() => document.readyState === 'complete'",
                        timeout=30000,
                    )
                    try:
                        await page.wait_for_load_state("networkidle", timeout=15000)
                    except Exception:
                        # 部分页面会持续有长连接，networkidle 可能达不到，忽略即可。
                        pass

                    # 用户反馈按钮点击过早，这里显式多等一段时间让页面脚本和动画稳定。
                    await page.wait_for_timeout(random.randint(2600, 4200))

                    self._trace("从姓名库选取姓名并申请短效邮箱")
                    picked_full_name, picked_email_username = pick_name_from_pool()
                    self.generated_full_name = picked_full_name
                    self._trace(f"选取姓名: {picked_full_name}, 邮箱用户名: {picked_email_username}")
                    email, jwt, temp_password = await asyncio.to_thread(
                        create_short_email, username=picked_email_username
                    )
                    self.temp_email = email
                    self.temp_email_jwt = jwt
                    self.temp_email_password = temp_password
                    self._trace(f"短效邮箱申请成功: {email}")

                    email_selector = (
                        "input[placeholder='username@example.com'], "
                        "input[type='text'][id^='formField']"
                    )
                    primary_continue_selector = (
                        "button[data-testid='test-primary-button']"
                    )
                    fallback_continue_selector = "button[type='submit']"

                    # 等待 Email 输入框 + Continue 按钮可见且可用。
                    self._trace("等待邮箱输入框和 Continue 按钮可用")
                    await page.wait_for_function(
                        f"""() => {{
                            const i = document.querySelector("{email_selector}");
                            const b = document.querySelector("{primary_continue_selector}") || document.querySelector("{fallback_continue_selector}");
                            if (!i || !b) return false;
                            const iVisible = !!(i.offsetParent || i.getClientRects().length);
                            const bVisible = !!(b.offsetParent || b.getClientRects().length);
                            const bEnabled = !b.disabled && b.getAttribute("aria-disabled") !== "true";
                            return iVisible && bVisible && bEnabled;
                        }}""",
                        timeout=60000,
                    )

                    email_input = page.locator(email_selector).first
                    await email_input.wait_for(timeout=60000)
                    await email_input.click()
                    try:
                        await email_input.press("Control+A")
                        await email_input.press("Backspace")
                    except Exception:
                        pass

                    await email_input.type(email, delay=random.randint(55, 110))
                    self._trace("邮箱输入完成")

                    # 确保输入框值已写入并触发 blur，避免按钮状态未更新。
                    await page.wait_for_function(
                        f"""(val) => {{
                            const i = document.querySelector("{email_selector}");
                            return !!i && i.value === val;
                        }}""",
                        arg=email,
                        timeout=15000,
                    )
                    try:
                        await email_input.press("Tab")
                    except Exception:
                        pass

                    await page.wait_for_timeout(random.randint(700, 1400))

                    continue_btn = page.locator(primary_continue_selector).first
                    if await continue_btn.count() == 0:
                        continue_btn = (
                            page.locator(fallback_continue_selector)
                            .filter(has_text="Continue")
                            .first
                        )
                    self._trace("已定位 Continue 按钮")

                    await continue_btn.wait_for(state="visible", timeout=60000)
                    await continue_btn.scroll_into_view_if_needed()
                    await page.wait_for_timeout(random.randint(700, 1500))

                    # 点击前记录上下文，便于判断是否提交成功。
                    before_ctx = await page.evaluate(
                        f"""() => {{
                            const headingEl = document.querySelector("h1, [data-testid='test-header'] h1");
                            const heading = headingEl ? (headingEl.textContent || "").trim() : "";
                            const emailInput = document.querySelector("{email_selector}");
                            const btn = document.querySelector("{primary_continue_selector}") || document.querySelector("{fallback_continue_selector}");
                            return {{
                                url: window.location.href,
                                heading,
                                emailPresent: !!emailInput,
                                emailValue: emailInput ? (emailInput.value || "") : "",
                                buttonText: btn ? (btn.textContent || "").trim() : "",
                            }};
                        }}"""
                    )

                    click_sent = False
                    self._trace("邮箱页 Continue 只点击一次，不重试")
                    box = None
                    try:
                        box = await continue_btn.bounding_box(timeout=0)
                    except Exception as box_err:
                        self._trace(
                            f"读取 Continue 坐标失败，转回退点击路径: {box_err}"
                        )
                    if box and box.get("width", 0) > 0 and box.get("height", 0) > 0:
                        cx = box["x"] + box["width"] / 2
                        cy = box["y"] + box["height"] / 2
                        jx = random.uniform(
                            -min(8.0, box["width"] / 5), min(8.0, box["width"] / 5)
                        )
                        jy = random.uniform(
                            -min(6.0, box["height"] / 5), min(6.0, box["height"] / 5)
                        )
                        tx = max(1.0, cx + jx)
                        ty = max(1.0, cy + jy)

                        sx = max(1.0, tx + random.uniform(-180, -70))
                        sy = max(1.0, ty + random.uniform(-90, 90))
                        await page.mouse.move(sx, sy)
                        await page.wait_for_timeout(random.randint(90, 220))

                        steps = random.randint(4, 7)
                        for step in range(1, steps + 1):
                            ratio = step / steps
                            mx = sx + (tx - sx) * ratio + random.uniform(-1.8, 1.8)
                            my = sy + (ty - sy) * ratio + random.uniform(-1.2, 1.2)
                            await page.mouse.move(mx, my)
                            await page.wait_for_timeout(random.randint(45, 110))

                        await continue_btn.hover()
                        await page.wait_for_timeout(random.randint(70, 180))
                        await page.mouse.down()
                        await page.wait_for_timeout(random.randint(45, 140))
                        await page.mouse.up()
                        click_sent = True
                        self._trace("Continue 已通过鼠标轨迹点击")
                    else:
                        try:
                            await continue_btn.click(timeout=10000)
                            click_sent = True
                            self._trace("Continue 已通过 locator.click 点击")
                        except Exception as click_err:
                            raise RuntimeError(
                                f"Continue 单次点击失败：{click_err}"
                            ) from click_err

                    if not click_sent:
                        raise RuntimeError("Continue 点击动作未执行成功")

                    await page.wait_for_timeout(random.randint(600, 1300))
                    self._trace("Continue 已点击，开始等待页面前进信号")

                    progressed = False
                    for _wait_round in range(45):
                        state_check = await page.evaluate(
                            f"""(before) => {{
                                const headingEl = document.querySelector("h1, [data-testid='test-header'] h1");
                                const heading = headingEl ? (headingEl.textContent || "").trim() : "";
                                const emailInput = document.querySelector("{email_selector}");
                                const urlChanged = window.location.href !== before.url;
                                const headingChanged = !!heading && heading !== before.heading;
                                const emailGone = !emailInput;
                                const emailChanged = !!emailInput && (emailInput.value || "") !== before.emailValue;
                                const codeInputVisible = !!document.querySelector("input[autocomplete='one-time-code'], input[name*='code'], input[id*='code']");
                                const pwdInputVisible = !!document.querySelector("input[type='password']");
                                const nameInputVisible = !!document.querySelector("div[data-testid='signup-full-name-input'] input");
                                return {{
                                    urlChanged,
                                    headingChanged,
                                    emailGone,
                                    emailChanged,
                                    codeInputVisible,
                                    pwdInputVisible,
                                    nameInputVisible,
                                }};
                            }}""",
                            before_ctx,
                        )
                        progressed = bool(
                            state_check.get("urlChanged")
                            or state_check.get("headingChanged")
                            or state_check.get("emailGone")
                            or state_check.get("codeInputVisible")
                            or state_check.get("pwdInputVisible")
                            or state_check.get("emailChanged")
                            or state_check.get("nameInputVisible")
                        )
                        self._trace(
                            "Continue 后状态: "
                            f"urlChanged={state_check.get('urlChanged')} "
                            f"headingChanged={state_check.get('headingChanged')} "
                            f"emailGone={state_check.get('emailGone')} "
                            f"emailChanged={state_check.get('emailChanged')} "
                            f"codeInputVisible={state_check.get('codeInputVisible')} "
                            f"pwdInputVisible={state_check.get('pwdInputVisible')} "
                            f"nameInputVisible={state_check.get('nameInputVisible')}"
                        )
                        if progressed:
                            self._trace("检测到页面已前进")
                            break
                        await page.wait_for_timeout(1000)

                    if not progressed:
                        self._trace("等待期间未检测到页面前进信号，继续后续步骤")

                    self.fill_submitted = True
                    self._trace("邮箱步骤提交成功")

                    # 新账号注册路径：如果出现“Enter your name”页面，则自动填写姓名并继续。
                    name_input_selector = (
                        "div[data-testid='signup-full-name-input'] input"
                    )
                    name_continue_selector = "button[data-testid='signup-next-button']"
                    try:
                        self._trace("检查是否进入姓名输入页")
                        await page.wait_for_selector(
                            name_input_selector, state="visible", timeout=60000
                        )
                        self._trace("检测到姓名输入页，开始自动填充姓名")
                        full_name = self.generated_full_name or generate_random_english_name()
                        self.generated_full_name = full_name

                        name_input = page.locator(name_input_selector).first
                        await name_input.click()
                        try:
                            await name_input.press("Control+A")
                            await name_input.press("Backspace")
                        except Exception:
                            pass
                        await name_input.type(full_name, delay=random.randint(50, 100))
                        self._trace(f"姓名输入完成: {full_name}")

                        await page.wait_for_function(
                            f"""(val) => {{
                                const i = document.querySelector("{name_input_selector}");
                                return !!i && i.value === val;
                            }}""",
                            arg=full_name,
                            timeout=12000,
                        )
                        await page.wait_for_function(
                            f"""() => {{
                                const b = document.querySelector("{name_continue_selector}");
                                return !!b && !b.disabled && b.getAttribute("aria-disabled") !== "true";
                            }}""",
                            timeout=12000,
                        )

                        name_continue_btn = page.locator(name_continue_selector).first
                        await name_continue_btn.wait_for(state="visible", timeout=15000)
                        await name_continue_btn.scroll_into_view_if_needed()
                        await page.wait_for_timeout(random.randint(500, 1000))

                        name_submitted = False
                        for _ in range(3):
                            self._trace(f"姓名页 Continue 点击尝试 {_ + 1}/3")
                            try:
                                await name_continue_btn.click(timeout=9000)
                                name_submitted = True
                                self._trace("姓名页 Continue 已通过 locator.click 点击")
                                break
                            except Exception:
                                pass
                            try:
                                await name_input.press("Enter")
                                name_submitted = True
                                self._trace("姓名页 Continue 已通过 Enter 提交")
                                break
                            except Exception:
                                pass
                            try:
                                await name_continue_btn.evaluate(
                                    """(btn) => {
                                        const f = btn.closest('form');
                                        if (f && typeof f.requestSubmit === 'function') {
                                            f.requestSubmit();
                                            return;
                                        }
                                        if (f) {
                                            f.submit();
                                            return;
                                        }
                                        btn.click();
                                    }"""
                                )
                                name_submitted = True
                                self._trace(
                                    "姓名页 Continue 已通过 requestSubmit/submit 提交"
                                )
                                break
                            except Exception:
                                pass
                            await page.wait_for_timeout(random.randint(300, 700))

                        if not name_submitted:
                            raise RuntimeError("姓名页 Continue 点击失败")

                        self.name_fill_submitted = True
                        self._trace("姓名步骤提交成功")
                    except Exception as name_err:
                        # 未出现姓名页时属于正常路径；出现但执行失败时上抛。
                        if self.generated_full_name:
                            self._trace(f"姓名步骤失败: {name_err}")
                            raise RuntimeError(
                                f"姓名自动填充失败：{name_err}"
                            ) from name_err
                        self._trace("未检测到姓名页，跳过姓名自动填充")

                    verify_code_input_selector = (
                        "div[data-testid='email-verification-form-code-input'] input"
                    )
                    verify_continue_selector = (
                        "button[data-testid='email-verification-verify-button']"
                    )
                    verify_page_detected = False
                    try:
                        self._trace("检查是否进入邮箱验证码页")
                        await page.wait_for_selector(
                            verify_code_input_selector, state="visible", timeout=60000
                        )
                        await page.wait_for_selector(
                            verify_continue_selector, state="visible", timeout=30000
                        )
                        verify_page_detected = True
                        self._trace("已进入邮箱验证码页")
                    except Exception:
                        self._trace("未检测到邮箱验证码页，跳过短效邮箱拉取")

                    if verify_page_detected:
                        if not self.temp_email_jwt:
                            self.shortmail_poll_error = (
                                "缺少短效邮箱 jwt，无法拉取邮件列表"
                            )
                            self._trace(self.shortmail_poll_error)
                        else:
                            try:
                                self._trace("开始轮询短效邮箱邮件（最多约 5 分钟）")
                                mail_json = await asyncio.to_thread(
                                    wait_for_shortmail_first_mail_json,
                                    self.temp_email_jwt,
                                    330,
                                    3.0,
                                )
                                self.shortmail_first_mail_json = mail_json
                                log("SHORTMAIL_MAIL_JSON_BEGIN")
                                print(
                                    json.dumps(mail_json, ensure_ascii=False, indent=2)
                                )
                                log("SHORTMAIL_MAIL_JSON_END")
                                self._trace("邮件原始 JSON 已打印，开始提取验证码")

                                verification_code = (
                                    extract_verification_code_from_shortmail_json(
                                        mail_json
                                    )
                                )
                                self.extracted_verification_code = verification_code
                                if not verification_code:
                                    raise RuntimeError(
                                        "未能从短效邮箱邮件内容中提取 6 位验证码"
                                    )
                                self._trace(f"验证码提取成功: {verification_code}")

                                code_input = page.locator(
                                    verify_code_input_selector
                                ).first
                                verify_btn = page.locator(
                                    verify_continue_selector
                                ).first
                                await code_input.wait_for(
                                    state="visible", timeout=30000
                                )
                                await verify_btn.wait_for(
                                    state="visible", timeout=30000
                                )

                                await code_input.click()
                                try:
                                    await code_input.press("Control+A")
                                    await code_input.press("Backspace")
                                except Exception:
                                    pass
                                await code_input.type(
                                    verification_code, delay=random.randint(40, 90)
                                )
                                self._trace("验证码输入完成")

                                await page.wait_for_function(
                                    f"""(val) => {{
                                        const i = document.querySelector("{verify_code_input_selector}");
                                        return !!i && i.value === val;
                                    }}""",
                                    arg=verification_code,
                                    timeout=10000,
                                )
                                await page.wait_for_timeout(random.randint(400, 900))

                                verify_clicked = False
                                try:
                                    await verify_btn.click(timeout=15000)
                                    verify_clicked = True
                                    self._trace("验证码页 Continue 点击成功")
                                except Exception as verify_click_err:
                                    self._trace(
                                        f"验证码页 Continue click 失败，尝试 Enter: {verify_click_err}"
                                    )

                                if not verify_clicked:
                                    try:
                                        await code_input.press("Enter")
                                        verify_clicked = True
                                        self._trace(
                                            "验证码页 Continue 已通过 Enter 提交"
                                        )
                                    except Exception as verify_enter_err:
                                        raise RuntimeError(
                                            f"验证码页 Continue 提交失败（click/Enter）：{verify_enter_err}"
                                        ) from verify_enter_err

                                self.verification_code_submitted = verify_clicked

                                password_input_selector = (
                                    "div[data-testid='test-input'] input[type='password'], "
                                    "input[placeholder='Enter password'][type='password']"
                                )
                                password_confirm_selector = (
                                    "div[data-testid='test-retype-input'] input[type='password'], "
                                    "input[placeholder='Re-enter password'][type='password']"
                                )
                                password_continue_selector = (
                                    "button[data-testid='test-primary-button']"
                                )
                                password_page_detected = False
                                try:
                                    self._trace("检查是否进入密码创建页")
                                    await page.wait_for_selector(
                                        password_input_selector,
                                        state="visible",
                                        timeout=120000,
                                    )
                                    await page.wait_for_selector(
                                        password_confirm_selector,
                                        state="visible",
                                        timeout=120000,
                                    )
                                    await page.wait_for_selector(
                                        password_continue_selector,
                                        state="visible",
                                        timeout=30000,
                                    )
                                    password_page_detected = True
                                    self._trace("已进入密码创建页")
                                except Exception:
                                    self._trace("未检测到密码创建页，跳过密码自动填充")

                                if password_page_detected:
                                    password_value = generate_strong_password()
                                    self.generated_password = password_value
                                    self._trace(
                                        f"本次随机密码已生成并填入: {password_value}"
                                    )

                                    pwd_input = page.locator(
                                        password_input_selector
                                    ).first
                                    repwd_input = page.locator(
                                        password_confirm_selector
                                    ).first
                                    pwd_continue_btn = page.locator(
                                        password_continue_selector
                                    ).first

                                    await pwd_input.click()
                                    try:
                                        await pwd_input.press("Control+A")
                                        await pwd_input.press("Backspace")
                                    except Exception:
                                        pass
                                    await pwd_input.type(
                                        password_value, delay=random.randint(35, 85)
                                    )

                                    await repwd_input.click()
                                    try:
                                        await repwd_input.press("Control+A")
                                        await repwd_input.press("Backspace")
                                    except Exception:
                                        pass
                                    await repwd_input.type(
                                        password_value, delay=random.randint(35, 85)
                                    )
                                    self._trace("密码与确认密码输入完成")

                                    await page.wait_for_function(
                                        f"""(pwd) => {{
                                            const p1 = document.querySelector("{password_input_selector}");
                                            const p2 = document.querySelector("{password_confirm_selector}");
                                            return !!p1 && !!p2 && p1.value === pwd && p2.value === pwd;
                                        }}""",
                                        arg=password_value,
                                        timeout=20000,
                                    )
                                    await page.wait_for_function(
                                        f"""() => {{
                                            const b = document.querySelector("{password_continue_selector}");
                                            return !!b && !b.disabled && b.getAttribute("aria-disabled") !== "true";
                                        }}""",
                                        timeout=20000,
                                    )
                                    await page.wait_for_timeout(
                                        random.randint(500, 1000)
                                    )

                                    pwd_submitted = False
                                    try:
                                        await pwd_continue_btn.click(timeout=20000)
                                        pwd_submitted = True
                                        self._trace("密码页 Continue 点击成功")
                                    except Exception as pwd_click_err:
                                        self._trace(
                                            f"密码页 Continue click 失败，尝试 Enter: {pwd_click_err}"
                                        )

                                    if not pwd_submitted:
                                        try:
                                            await repwd_input.press("Enter")
                                            pwd_submitted = True
                                            self._trace(
                                                "密码页 Continue 已通过 Enter 提交"
                                            )
                                        except Exception as pwd_enter_err:
                                            raise RuntimeError(
                                                f"密码页 Continue 提交失败（click/Enter）：{pwd_enter_err}"
                                            ) from pwd_enter_err

                                    self.password_submitted = pwd_submitted

                                allow_access_selector = (
                                    "button[data-testid='allow-access-button']"
                                )
                                try:
                                    self._trace(
                                        "检查是否进入授权确认页（Allow access）"
                                    )
                                    await page.wait_for_selector(
                                        allow_access_selector,
                                        state="visible",
                                        timeout=180000,
                                    )
                                    allow_btn = page.locator(
                                        allow_access_selector
                                    ).first
                                    await allow_btn.scroll_into_view_if_needed()
                                    await page.wait_for_timeout(
                                        random.randint(400, 900)
                                    )
                                    await allow_btn.click(timeout=20000)
                                    self.allow_access_clicked = True
                                    self._trace(
                                        "Allow access 点击成功，注册流程收尾完成"
                                    )
                                except Exception as allow_err:
                                    self._trace(
                                        f"未完成 Allow access 点击：{allow_err}"
                                    )
                            except Exception as poll_err:
                                self.shortmail_poll_error = str(poll_err)
                                self._trace(
                                    f"拉取短效邮箱邮件失败: {self.shortmail_poll_error}"
                                )
                except Exception as autofill_err:
                    self.autofill_error = str(autofill_err)
                    self._trace(f"自动填充流程失败: {self.autofill_error}")
                    raise

            self.started_ok = True
            self._trace("自动化启动阶段完成")
            if self.auto_fill_email:
                self.detail = (
                    f"camoufox(headless={self.headless}, os={selected_os}, "
                    f"autofill_email={self.temp_email}, submitted={self.fill_submitted}, "
                    f"autofill_name={self.generated_full_name}, name_submitted={self.name_fill_submitted}, "
                    f"shortmail_mail_found={self.shortmail_first_mail_json is not None}, "
                    f"verification_code={self.extracted_verification_code}, "
                    f"verification_submitted={self.verification_code_submitted}, "
                    f"generated_password={self.generated_password}, "
                    f"password_submitted={self.password_submitted}, "
                    f"allow_access_clicked={self.allow_access_clicked}, "
                    f"shortmail_poll_error={self.shortmail_poll_error}, "
                    f"autofill_error={self.autofill_error})"
                )
            else:
                self.detail = f"camoufox(headless={self.headless}, os={selected_os}, autofill_email=False)"
            self.ready_event.set()

            while not self.stop_event.is_set():
                await asyncio.sleep(0.2)
        except Exception as e:
            self.error = f"Camoufox 启动/打开失败: {e}"
            self._trace(self.error)
            self.ready_event.set()
        finally:
            try:
                if context is not None:
                    await context.close()
            except Exception:
                pass
            try:
                if camoufox_obj is not None:
                    await camoufox_obj.__aexit__(None, None, None)
            except Exception:
                pass
            self._trace("浏览器会话已结束")

    def wait_ready(self, timeout_s: Optional[int]) -> bool:
        if timeout_s is None or timeout_s <= 0:
            self.ready_event.wait()
            return True
        return self.ready_event.wait(timeout=timeout_s)

    def close(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=10)


def open_url_in_camoufox(
    url: str,
    headless: bool = False,
    os_name: str = "auto",
    auto_fill_email: bool = True,
    startup_timeout_s: Optional[int] = None,
) -> tuple[bool, str, Optional[CamoufoxSession]]:
    session = CamoufoxSession(
        url=url,
        headless=headless,
        os_name=os_name,
        auto_fill_email=auto_fill_email,
    )
    session.start()
    ready = session.wait_ready(startup_timeout_s)
    if not ready:
        timeout_desc = (
            f"{startup_timeout_s} 秒" if startup_timeout_s is not None else "未设置"
        )
        return (
            False,
            f"Camoufox 启动/自动填充等待超时（{timeout_desc}）",
            session,
        )
    if session.started_ok:
        return True, session.detail, session
    return False, session.error or "Camoufox 启动失败", session


def open_url_in_private_window(url: str, browser: str = "auto") -> tuple[bool, str]:
    """
    在无痕/隐私模式下打开 URL。
    返回: (是否成功, 说明信息)
    """
    browser = browser.lower().strip() or "auto"
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")

    def exists(path: str) -> bool:
        return bool(path) and os.path.exists(path)

    # Chromium 系列
    edge_paths = [
        os.path.join(
            program_files_x86, "Microsoft", "Edge", "Application", "msedge.exe"
        ),
        os.path.join(program_files, "Microsoft", "Edge", "Application", "msedge.exe"),
    ]
    chrome_paths = [
        os.path.join(
            program_files_x86, "Google", "Chrome", "Application", "chrome.exe"
        ),
        os.path.join(program_files, "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(local_app_data, "Google", "Chrome", "Application", "chrome.exe"),
    ]
    brave_paths = [
        os.path.join(
            program_files_x86,
            "BraveSoftware",
            "Brave-Browser",
            "Application",
            "brave.exe",
        ),
        os.path.join(
            program_files, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"
        ),
        os.path.join(
            local_app_data, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"
        ),
    ]
    firefox_paths = [
        os.path.join(program_files, "Mozilla Firefox", "firefox.exe"),
        os.path.join(program_files_x86, "Mozilla Firefox", "firefox.exe"),
    ]

    candidates: list[tuple[str, list[str]]] = []
    if browser in ("auto", "edge"):
        for p in edge_paths:
            if exists(p):
                candidates.append(("edge", [p, "--inprivate", "--new-window", url]))
        candidates.append(("edge", ["msedge", "--inprivate", "--new-window", url]))
    if browser in ("auto", "chrome"):
        for p in chrome_paths:
            if exists(p):
                candidates.append(("chrome", [p, "--incognito", "--new-window", url]))
        candidates.append(("chrome", ["chrome", "--incognito", "--new-window", url]))
    if browser in ("auto", "brave"):
        for p in brave_paths:
            if exists(p):
                candidates.append(("brave", [p, "--incognito", "--new-window", url]))
        candidates.append(("brave", ["brave", "--incognito", "--new-window", url]))
    if browser in ("auto", "firefox"):
        for p in firefox_paths:
            if exists(p):
                candidates.append(("firefox", [p, "-private-window", url]))
        candidates.append(("firefox", ["firefox", "-private-window", url]))

    for name, cmd in candidates:
        try:
            subprocess.Popen(cmd)
            return True, f"{name}: {' '.join(cmd[:3])} ..."
        except Exception:
            continue

    # 兜底：系统默认浏览器（非严格无痕）
    opened = webbrowser.open(url)
    if opened:
        return True, "fallback: webbrowser.open(默认浏览器，无法保证无痕)"
    return False, "未找到可用浏览器命令，且默认浏览器打开失败"


def resolve_profile_arn(explicit_profile_arn: str, login_option: str) -> Optional[str]:
    explicit = explicit_profile_arn.strip()
    if explicit:
        return explicit
    return APP_CONFIG.fixed_profile_arns.get(login_option.lower())


def verify_bearer_credential(
    session: requests.Session,
    authorization_header: str,
    idc_region: str,
    profile_arn: str,
) -> dict[str, Any]:
    headers = {
        "Authorization": authorization_header,
        "accept": "application/json",
        "x-amz-user-agent": "aws-sdk-js/1.0.0 KiroIDE-script",
    }
    base = f"https://q.{idc_region}.amazonaws.com"

    out: dict[str, Any] = {
        "region": idc_region,
        "profile_arn": profile_arn,
        "get_usage_limits": {},
        "list_available_models": {},
    }

    # 1) getUsageLimits
    usage_url = f"{base}/getUsageLimits"
    usage_params = {
        "origin": "AI_EDITOR",
        "profileArn": profile_arn,
        "resourceType": "AGENTIC_REQUEST",
    }
    usage_resp = session.get(
        usage_url, headers=headers, params=usage_params, timeout=20
    )
    usage_text = usage_resp.text
    usage_json: Optional[dict[str, Any]] = None
    try:
        usage_json = usage_resp.json()
    except Exception:
        usage_json = None
    out["get_usage_limits"] = {
        "status_code": usage_resp.status_code,
        "ok": usage_resp.ok,
        "response_json": usage_json,
        "response_text_preview": usage_text[:500] if usage_text else "",
    }

    # 2) ListAvailableModels
    models_url = f"{base}/ListAvailableModels"
    models_params = {
        "origin": "AI_EDITOR",
        "profileArn": profile_arn,
    }
    models_resp = session.get(
        models_url, headers=headers, params=models_params, timeout=20
    )
    models_text = models_resp.text
    models_json: Optional[dict[str, Any]] = None
    try:
        models_json = models_resp.json()
    except Exception:
        models_json = None
    model_count = None
    default_model_id = None
    if isinstance(models_json, dict):
        models = models_json.get("models")
        if isinstance(models, list):
            model_count = len(models)
        default_model = models_json.get("defaultModel")
        if isinstance(default_model, dict):
            default_model_id = default_model.get("modelId")
    out["list_available_models"] = {
        "status_code": models_resp.status_code,
        "ok": models_resp.ok,
        "model_count": model_count,
        "default_model_id": default_model_id,
        "response_json": models_json,
        "response_text_preview": models_text[:500] if models_text else "",
    }

    out["is_valid_for_kiro_q"] = bool(
        out["get_usage_limits"].get("ok") and out["list_available_models"].get("ok")
    )
    return out


@dataclass
class CallbackResult:
    stage: str
    path: str
    raw_query: str
    params: dict[str, str]
    state: Optional[str]
    state_valid: Optional[bool]
    received_at: float


class CallbackState:
    def __init__(self, expected_stage1_state: str):
        self.expected_stage1_state = expected_stage1_state
        self.expected_stage2_state: Optional[str] = None
        self.stage1_event = threading.Event()
        self.stage2_event = threading.Event()
        self.stage1_result: Optional[CallbackResult] = None
        self.stage2_result: Optional[CallbackResult] = None
        self.lock = threading.Lock()

    def set_stage2_state(self, state: str) -> None:
        with self.lock:
            self.expected_stage2_state = state

    def set_stage1_once(self, result: CallbackResult) -> None:
        with self.lock:
            if self.stage1_result is None:
                self.stage1_result = result
                self.stage1_event.set()

    def set_stage2_once(self, result: CallbackResult) -> None:
        with self.lock:
            if self.stage2_result is None:
                self.stage2_result = result
                self.stage2_event.set()


def _flatten_query(qs: dict[str, list[str]]) -> dict[str, str]:
    return {k: v[0] if v else "" for k, v in qs.items()}


def make_handler(shared: CallbackState, success_redirect_url: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args):  # noqa: D401
            return

        def _write_302(self) -> None:
            self.send_response(302)
            self.send_header("Access-Control-Allow-Methods", "GET")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Location", success_redirect_url)
            self.send_header("Connection", "close")
            self.end_headers()

        def _write_404(self) -> None:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write("Not Found".encode("utf-8"))

        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query, keep_blank_values=True)
            params = _flatten_query(query)
            state = params.get("state")
            ts = time.time()

            if parsed.path in ("/", "/signin/callback"):
                expected = shared.expected_stage1_state
                result = CallbackResult(
                    stage="stage1",
                    path=parsed.path,
                    raw_query=parsed.query,
                    params=params,
                    state=state,
                    state_valid=(state == expected) if state is not None else None,
                    received_at=ts,
                )
                shared.set_stage1_once(result)
                self._write_302()
                return

            if parsed.path == "/oauth/callback":
                expected = shared.expected_stage2_state
                result = CallbackResult(
                    stage="stage2",
                    path=parsed.path,
                    raw_query=parsed.query,
                    params=params,
                    state=state,
                    state_valid=(state == expected)
                    if expected is not None and state is not None
                    else None,
                    received_at=ts,
                )
                shared.set_stage2_once(result)
                self._write_302()
                return

            self._write_404()

    return Handler


class LocalCallbackServer:
    def __init__(
        self, host: str, port: int, shared: CallbackState, success_redirect_url: str
    ):
        self.host = host
        self.port = port
        self.shared = shared
        self.success_redirect_url = success_redirect_url
        self.server = ThreadingHTTPServer(
            (host, port), make_handler(shared, success_redirect_url)
        )
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=2)


def new_http_session() -> requests.Session:
    s = requests.Session()
    # 避免系统代理导致的请求偏转/失败
    s.trust_env = False
    return s


def initiate_login(
    session: requests.Session,
    portal_url: str,
    idp: str,
    state: str,
    code_challenge: str,
    redirect_uri: str,
    redirect_from: str,
    idc_region: Optional[str],
    start_url: Optional[str],
) -> dict[str, Any]:
    url = f"{portal_url.rstrip('/')}{APP_CONFIG.initiate_login_path}"
    payload: dict[str, Any] = {
        "idp": idp,
        "state": state,
        "codeChallenge": code_challenge,
        "codeChallengeMethod": "S256",
        "redirectUri": redirect_uri,
        "redirectFrom": redirect_from,
    }
    if idp in {"AWSIdC", "Internal"}:
        if idc_region:
            payload["idcRegion"] = idc_region
        if start_url:
            payload["startUrl"] = start_url

    headers = {
        "content-type": "application/cbor",
        "accept": "application/cbor",
        "smithy-protocol": "rpc-v2-cbor",
        "origin": portal_url.rstrip("/"),
        "x-kiro-visitorid": make_visitor_id(),
    }
    resp = session.post(url, data=cbor2.dumps(payload), headers=headers, timeout=20)
    resp.raise_for_status()
    if "application/cbor" in (resp.headers.get("content-type") or ""):
        return cbor2.loads(resp.content)
    return {"raw": resp.text}


def register_oidc_client(
    session: requests.Session,
    idc_region: str,
    issuer_url: str,
    scopes: list[str],
    register_redirect_uri: str,
) -> dict[str, Any]:
    url = f"https://oidc.{idc_region}.amazonaws.com/client/register"
    payload = {
        "clientName": "Kiro IDE",
        "clientType": "public",
        "scopes": scopes,
        "grantTypes": ["authorization_code", "refresh_token"],
        "redirectUris": [register_redirect_uri],
        "issuerUrl": issuer_url,
    }
    resp = session.post(url, json=payload, timeout=20)
    resp.raise_for_status()
    return resp.json()


def build_authorize_url(
    idc_region: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    scopes: list[str],
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        # 与 Kiro 一致：scopes 用逗号拼接
        "scopes": ",".join(scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"https://oidc.{idc_region}.amazonaws.com/authorize?{urlencode(params)}"


def exchange_token(
    session: requests.Session,
    idc_region: str,
    client_id: str,
    client_secret: str,
    code: str,
    code_verifier: str,
    redirect_uri: str,
) -> dict[str, Any]:
    url = f"https://oidc.{idc_region}.amazonaws.com/token"
    payload = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "grantType": "authorization_code",
        "redirectUri": redirect_uri,
        "code": code,
        "codeVerifier": code_verifier,
    }
    resp = session.post(url, json=payload, timeout=20)
    resp.raise_for_status()
    return resp.json()


def stage1_fallback_from_redirect_url(
    redirect_url: str, expected_state: str
) -> Optional[CallbackResult]:
    parsed = urlparse(redirect_url)
    if not parsed.query:
        return None
    params = _flatten_query(parse_qs(parsed.query, keep_blank_values=True))
    state = params.get("state")
    return CallbackResult(
        stage="stage1",
        path=parsed.path or "/",
        raw_query=parsed.query,
        params=params,
        state=state,
        state_valid=(state == expected_state) if state is not None else None,
        received_at=time.time(),
    )


def main() -> None:
    config = FLOW_CONFIG
    should_exchange_token = config.exchange_token
    token_file = build_default_token_file()
    mail_file: Optional[str] = None
    port = config.callback_port or ensure_available_port(APP_CONFIG.callback_ports)
    token_output: Optional[dict[str, Any]] = None

    # 第一阶段参数（Portal /signin + InitiateLogin）
    stage1_state = str(uuid.uuid4())
    stage1_code_verifier = generate_code_verifier()
    stage1_code_challenge = generate_code_challenge(stage1_code_verifier)
    redirect_uri_stage1 = f"http://localhost:{port}"
    signin_url = build_portal_signin_url(
        portal_url=config.portal_url,
        state=stage1_state,
        code_challenge=stage1_code_challenge,
        redirect_uri=redirect_uri_stage1,
        redirect_from=config.redirect_from,
    )

    success_redirect = f"{config.portal_url.rstrip('/')}/signin?auth_status=success&redirect_from={config.redirect_from}"
    shared = CallbackState(expected_stage1_state=stage1_state)
    server = LocalCallbackServer("127.0.0.1", port, shared, success_redirect)

    final: dict[str, Any] = {
        "portal": {
            "signin_url": signin_url,
            "state": stage1_state,
            "code_verifier": stage1_code_verifier,
            "code_challenge": stage1_code_challenge,
            "redirect_uri": redirect_uri_stage1,
            "redirect_from": config.redirect_from,
        },
        "stage1": {},
        "stage2": {},
        "register_client": {},
        "token_exchange": {},
        "token_output": [],
    }

    session = new_http_session()
    camoufox_session: Optional[CamoufoxSession] = None

    log("步骤 1/7：启动本地回调服务")
    log(f"监听地址：http://127.0.0.1:{port}")
    server.start()

    try:
        log("步骤 2/7：生成并展示第一阶段参数（Portal + PKCE）")
        log(f"signin_url = {signin_url}")
        log(f"state = {stage1_state}")
        log(f"code_verifier = {stage1_code_verifier}")
        log(f"code_challenge = {stage1_code_challenge}")

        log("步骤 3/7：调用 InitiateLogin（CBOR）")
        initiate_resp = initiate_login(
            session=session,
            portal_url=config.portal_url,
            idp=config.idp,
            state=stage1_state,
            code_challenge=stage1_code_challenge,
            redirect_uri=redirect_uri_stage1,
            redirect_from=config.redirect_from,
            idc_region=config.idc_region,
            start_url=config.start_url,
        )
        final["stage1"]["initiate_login_response"] = initiate_resp
        log(f"InitiateLogin 返回：{json.dumps(initiate_resp, ensure_ascii=False)}")

        redirect_url = initiate_resp.get("redirectUrl")
        if not redirect_url:
            raise RuntimeError("InitiateLogin 响应里没有 redirectUrl，无法继续")

        log("步骤 4/7：触发第一层回调并提取 issuer_url / idc_region")
        log(f"第一层回调地址：{redirect_url}")
        try:
            r1 = session.get(redirect_url, allow_redirects=False, timeout=15)
            log(f"已请求第一层回调地址，HTTP 状态：{r1.status_code}")
        except Exception as err:
            log(f"请求第一层回调地址失败：{err}")

        if not shared.stage1_event.wait(timeout=10):
            log("本地服务未收到第一层回调，尝试从 redirectUrl 直接解析参数")
            fallback = stage1_fallback_from_redirect_url(redirect_url, stage1_state)
            if fallback is not None:
                shared.set_stage1_once(fallback)

        stage1_result = shared.stage1_result
        if stage1_result is None:
            raise RuntimeError("第一层回调未拿到，流程中断")

        final["stage1"]["callback"] = asdict(stage1_result)
        log(
            f"第一层回调 path={stage1_result.path} state_valid={stage1_result.state_valid}"
        )
        if stage1_result.state_valid is False:
            raise RuntimeError("第一层回调 state 校验失败")

        issuer_url = (
            stage1_result.params.get("issuer_url")
            or stage1_result.params.get("issuerUrl")
            or config.start_url
        )
        idc_region = (
            stage1_result.params.get("idc_region")
            or stage1_result.params.get("idcRegion")
            or initiate_resp.get("instanceRegion")
            or config.idc_region
        )
        login_option = stage1_result.params.get("login_option", "").lower()
        if not login_option:
            login_option = config.idp.lower()

        final["stage1"]["resolved"] = {
            "login_option": login_option,
            "issuer_url": issuer_url,
            "idc_region": idc_region,
        }
        log(
            f"解析结果：login_option={login_option} issuer_url={issuer_url} idc_region={idc_region}"
        )

        if login_option in {"google", "github"}:
            log(
                "当前登录选项属于社交登录，后续应走 Kiro /oauth/token 交换。此脚本重点是 IdC 链路，先到此为止。"
            )
            if config.output_json:
                print(json.dumps(final, ensure_ascii=False, indent=2))
            return

        log("步骤 5/7：注册 AWS OIDC Client（/client/register）")
        reg = register_oidc_client(
            session=session,
            idc_region=idc_region,
            issuer_url=issuer_url,
            scopes=APP_CONFIG.kiro_grant_scopes,
            register_redirect_uri=config.register_redirect_uri,
        )
        final["register_client"] = reg
        client_id = reg.get("clientId")
        client_secret = reg.get("clientSecret")
        if not client_id or not client_secret:
            raise RuntimeError("client/register 未返回 clientId 或 clientSecret")
        log(f"注册成功：clientId={client_id}")

        log("步骤 6/7：构造 AWS 授权地址并等待第二层回调（/oauth/callback）")
        stage2_state = str(uuid.uuid4())
        shared.set_stage2_state(stage2_state)
        stage2_code_verifier = generate_code_verifier()
        stage2_code_challenge = generate_code_challenge(stage2_code_verifier)
        stage2_redirect_uri = f"http://127.0.0.1:{port}/oauth/callback"
        authorize_url = build_authorize_url(
            idc_region=idc_region,
            client_id=client_id,
            redirect_uri=stage2_redirect_uri,
            state=stage2_state,
            code_challenge=stage2_code_challenge,
            scopes=APP_CONFIG.kiro_grant_scopes,
        )

        final["stage2"]["authorize"] = {
            "url": authorize_url,
            "state": stage2_state,
            "code_verifier": stage2_code_verifier,
            "code_challenge": stage2_code_challenge,
            "redirect_uri": stage2_redirect_uri,
            "idc_region": idc_region,
        }
        log(f"AWS 授权地址：{authorize_url}")
        if not config.open_browser:
            log("当前配置为不自动打开浏览器，请手动在浏览器打开上面的授权地址")
        else:
            if config.browser == "camoufox":
                opened, detail, camoufox_session = open_url_in_camoufox(
                    authorize_url,
                    headless=config.camoufox_headless,
                    os_name=config.camoufox_os,
                    auto_fill_email=config.camoufox_autofill_email,
                    startup_timeout_s=config.camoufox_startup_timeout_s,
                )
            else:
                opened, detail = open_url_in_private_window(
                    authorize_url, browser=config.browser
                )
            final["stage2"]["authorize"]["browser_open"] = {
                "opened": opened,
                "mode": "camoufox" if config.browser == "camoufox" else "private",
                "browser": config.browser,
                "detail": detail,
            }
            if camoufox_session is not None:
                final["stage2"]["authorize"]["browser_open"]["temp_email"] = (
                    camoufox_session.temp_email
                )
                final["stage2"]["authorize"]["browser_open"]["temp_email_jwt"] = (
                    camoufox_session.temp_email_jwt
                )
                final["stage2"]["authorize"]["browser_open"]["temp_email_password"] = (
                    camoufox_session.temp_email_password
                )
                final["stage2"]["authorize"]["browser_open"]["email_submitted"] = (
                    camoufox_session.fill_submitted
                )
                final["stage2"]["authorize"]["browser_open"]["generated_full_name"] = (
                    camoufox_session.generated_full_name
                )
                final["stage2"]["authorize"]["browser_open"]["name_submitted"] = (
                    camoufox_session.name_fill_submitted
                )
                final["stage2"]["authorize"]["browser_open"][
                    "shortmail_first_mail_json"
                ] = camoufox_session.shortmail_first_mail_json
                final["stage2"]["authorize"]["browser_open"]["shortmail_poll_error"] = (
                    camoufox_session.shortmail_poll_error
                )
                final["stage2"]["authorize"]["browser_open"][
                    "extracted_verification_code"
                ] = camoufox_session.extracted_verification_code
                final["stage2"]["authorize"]["browser_open"][
                    "verification_code_submitted"
                ] = camoufox_session.verification_code_submitted
                final["stage2"]["authorize"]["browser_open"]["generated_password"] = (
                    camoufox_session.generated_password
                )
                final["stage2"]["authorize"]["browser_open"]["password_submitted"] = (
                    camoufox_session.password_submitted
                )
                final["stage2"]["authorize"]["browser_open"]["allow_access_clicked"] = (
                    camoufox_session.allow_access_clicked
                )
                final["stage2"]["authorize"]["browser_open"]["email_autofill_error"] = (
                    camoufox_session.autofill_error
                )
            if config.browser == "camoufox":
                log(
                    "已尝试用 Camoufox 打开授权页："
                    f"{'成功' if opened else '失败'}；"
                    f"{detail}"
                )
                if not opened:
                    raise RuntimeError(
                        f"Camoufox 打开/邮箱填充失败，流程终止：{detail}"
                    )
                if opened and config.camoufox_headless:
                    log("当前为 Camoufox headless 模式，页面不可见。")
            else:
                log(
                    "已尝试无痕窗口打开浏览器："
                    f"{'成功' if opened else '失败'}；"
                    f"{detail}"
                )

        log(f"等待第二层回调，超时 {config.timeout_s} 秒...")
        got_stage2 = shared.stage2_event.wait(timeout=config.timeout_s)
        if not got_stage2:
            log("超时：未收到 /oauth/callback。请检查浏览器是否完成 AWS 登录。")
        stage2_result = shared.stage2_result
        if stage2_result is not None:
            final["stage2"]["callback"] = asdict(stage2_result)
            log(
                f"第二层回调 path={stage2_result.path} state_valid={stage2_result.state_valid}"
            )
            auth_code = stage2_result.params.get("code")
            if auth_code:
                log(f"已收到 authorization code（前32位）：{auth_code[:32]}...")
            else:
                log("第二层回调里未发现 code 字段")

            log("步骤 7/7：输出可用于换 token 的关键参数")
            log(f"code_verifier（第二阶段）= {stage2_code_verifier}")

            if (
                should_exchange_token
                and auth_code
                and stage2_result.state_valid is not False
            ):
                log("开始调用 AWS OIDC /token 交换 token")
                token_resp = exchange_token(
                    session=session,
                    idc_region=idc_region,
                    client_id=client_id,
                    client_secret=client_secret,
                    code=auth_code,
                    code_verifier=stage2_code_verifier,
                    redirect_uri=stage2_redirect_uri,
                )
                final["token_exchange"] = token_resp
                refresh_token = str(token_resp.get("refreshToken", "") or "")
                if not refresh_token:
                    raise RuntimeError(
                        "token 响应未返回 refreshToken，无法生成最终文件"
                    )
                access_token = str(token_resp.get("accessToken", "") or "")
                resolved_profile_arn = resolve_profile_arn(
                    config.profile_arn, login_option
                ) or ""
                temp_email = (
                    camoufox_session.temp_email
                    if camoufox_session is not None
                    else ""
                ) or ""
                token_output = build_refresh_token_bundle(
                    refresh_token=refresh_token,
                    access_token=access_token,
                    client_id=str(client_id),
                    client_secret=str(client_secret),
                    region=idc_region,
                    email=temp_email,
                    profile_arn=resolved_profile_arn,
                    start_url=config.start_url or "https://view.awsapps.com/start",
                )
                final["token_output"] = token_output
                log("token 交换成功，已生成完整凭据文件")

                if config.verify_credential:
                    access_token = str(token_resp.get("accessToken", "") or "")
                    profile_arn = resolve_profile_arn(config.profile_arn, login_option)
                    if not access_token:
                        final["credential_verify"] = {
                            "status": "unknown",
                            "reason": "missing_access_token",
                        }
                        log("校验跳过：token 响应缺少 accessToken")
                    elif not profile_arn:
                        final["credential_verify"] = {
                            "status": "unknown",
                            "reason": "missing_profile_arn",
                        }
                        log("校验跳过：未提供 profileArn，且未匹配默认值")
                    else:
                        verify = verify_bearer_credential(
                            session=session,
                            authorization_header=f"Bearer {access_token}",
                            idc_region=idc_region,
                            profile_arn=profile_arn,
                        )
                        is_valid = bool(verify.get("is_valid_for_kiro_q"))
                        status = "ok" if is_valid else "blocked_or_invalid"
                        final["credential_verify"] = {
                            "status": status,
                            "detail": verify,
                        }
                        log(f"账号验证结果：{status}")
            elif not should_exchange_token:
                log("当前配置已禁用 token 交换")

    except Exception as e:
        final["error"] = str(e)
        log(f"流程失败：{e}")
    finally:
        if camoufox_session is not None:
            try:
                camoufox_session.close()
                log("Camoufox 会话已关闭")
            except Exception as e:
                log(f"关闭 Camoufox 会话失败：{e}")
        server.stop()
        log("本地回调服务已关闭")

    if camoufox_session is not None and camoufox_session.temp_email:
        token_file = build_default_token_file(camoufox_session.temp_email)
        mail_file = build_mail_output_file(token_file)

    if config.save_result:
        if token_output is None:
            log("未生成最终 token 文件：请确认第二层回调与 token 交换已成功完成")
        try:
            if token_output is not None:
                save_json_file(token_file, token_output)
                final["token_output_file"] = token_file
                log(f"最终 token 文件已保存：{token_file}")
            if mail_file and camoufox_session is not None:
                mail_payload = {
                    "temp_email": camoufox_session.temp_email,
                    "temp_email_password": camoufox_session.temp_email_password,
                    "temp_email_jwt": camoufox_session.temp_email_jwt,
                    "builder_id_password": camoufox_session.generated_password,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
                }
                save_json_file(mail_file, mail_payload)
                final["shortmail_file"] = mail_file
                log(f"临时邮箱文件已保存：{mail_file}")
            result_file = build_result_output_file(token_file)
            save_json_file(result_file, final)
            final["result_file"] = result_file
            log(f"完整结果文件已保存：{result_file}")
        except Exception as save_err:
            final["save_error"] = str(save_err)
            log(f"保存最终 token 文件失败：{save_err}")

    if config.output_json:
        if token_output is not None:
            print(json.dumps(token_output, ensure_ascii=False, indent=2))
        else:
            print(json.dumps(final, ensure_ascii=False, indent=2))
    else:
        log("流程结束。")
        if "error" in final:
            log("结果：失败")
        else:
            log("结果：已执行完成（是否登录成功取决于你是否在浏览器完成第二阶段）")


if __name__ == "__main__":
    main()
