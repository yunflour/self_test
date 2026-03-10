#!/usr/bin/env python3
"""
AWS Builder ID MFA (TOTP) registration workflow driver.

This script automates the same workflow observed in browser traffic:
1) start
2) get-users-mfa-type
3) get-totp-registration-credential (get seed + mfaDeviceId)
4) get-totp-registration-credential (submit TOTP code)

It requires a valid logged-in browser session cookie and matching context
values (fingerprint / visitorId) from the same session.
"""

from __future__ import annotations

import argparse
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import format_datetime
from typing import Any

import pyotp
import requests


def now_rfc2822_gmt() -> str:
    # Match browser-like x-amz-date style, e.g. Tue, 10 Mar 2026 12:20:03 GMT
    return format_datetime(datetime.now(timezone.utc), usegmt=True)


def compact(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


@dataclass
class Context:
    host: str
    identity_pool_id: str
    username: str
    cookie: str
    fingerprint: str
    visitor_id: str
    workflow_state_handle: str


def post_register(
    session: requests.Session,
    ctx: Context,
    payload: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    url = f"https://{ctx.host}/platform/{ctx.identity_pool_id}/mfa/api/register"
    headers = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json; charset=UTF-8",
        "origin": f"https://{ctx.host}",
        "referer": (
            f"https://{ctx.host}/platform/{ctx.identity_pool_id}/mfa/register"
            f"?workflowStateHandle={ctx.workflow_state_handle}"
        ),
        "x-amz-date": now_rfc2822_gmt(),
        "x-amzn-requestid": str(uuid.uuid4()),
        "cookie": ctx.cookie,
    }
    resp = session.post(url, data=compact(payload), headers=headers, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bind AWS Builder ID MFA (TOTP) through workflow API"
    )
    parser.add_argument(
        "--host",
        default="us-east-1.signin.aws",
        help="MFA workflow host, default: us-east-1.signin.aws",
    )
    parser.add_argument(
        "--identity-pool-id",
        required=True,
        help="Identity pool id, e.g. d-9067642ac7",
    )
    parser.add_argument("--username", required=True, help="Builder ID email")
    parser.add_argument(
        "--workflow-state-handle",
        required=True,
        help="Initial workflowStateHandle from register URL",
    )
    parser.add_argument(
        "--cookie",
        required=True,
        help="Full Cookie header from the same logged-in browser session",
    )
    parser.add_argument(
        "--fingerprint",
        required=True,
        help="FingerPrintRequestInput value, starts with ECdITeCs:",
    )
    parser.add_argument(
        "--visitor-id",
        required=True,
        help="visitorId observed in workflow requests",
    )
    parser.add_argument(
        "--totp-code",
        help="6-digit TOTP code to submit. If omitted, use --seed to generate.",
    )
    parser.add_argument(
        "--seed",
        help="TOTP seed (base32). If omitted, script uses seed from step 3 response.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="HTTP timeout seconds, default: 20",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full step responses",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ctx = Context(
        host=args.host,
        identity_pool_id=args.identity_pool_id,
        username=args.username,
        cookie=args.cookie,
        fingerprint=args.fingerprint,
        visitor_id=args.visitor_id,
        workflow_state_handle=args.workflow_state_handle,
    )

    session = requests.Session()
    session.trust_env = False

    # Step 1: start
    payload_start = {
        "stepId": "start",
        "workflowStateHandle": ctx.workflow_state_handle,
        "inputs": [
            {"input_type": "UserRequestInput", "username": ctx.username},
            {
                "input_type": "FingerPrintRequestInput",
                "fingerPrint": ctx.fingerprint,
            },
        ],
        "requestId": str(uuid.uuid4()),
    }
    step1 = post_register(session, ctx, payload_start, args.timeout)
    if args.verbose:
        print("[step1/start]", json.dumps(step1, ensure_ascii=False, indent=2))

    ws2 = str(step1.get("workflowStateHandle", "") or "")
    if not ws2:
        raise RuntimeError("step1 did not return workflowStateHandle")

    # Step 2: select TOTP
    payload_mfa_type = {
        "stepId": "get-users-mfa-type",
        "workflowStateHandle": ws2,
        "actionId": "SUBMIT",
        "inputs": [
            {"input_type": "MFATypeRequestInput", "mfaType": "TOTP"},
            {"input_type": "UserRequestInput", "username": ctx.username},
            {
                "input_type": "FingerPrintRequestInput",
                "fingerPrint": ctx.fingerprint,
            },
        ],
        "visitorId": ctx.visitor_id,
        "requestId": str(uuid.uuid4()),
    }
    step2 = post_register(session, ctx, payload_mfa_type, args.timeout)
    if args.verbose:
        print(
            "[step2/get-users-mfa-type]",
            json.dumps(step2, ensure_ascii=False, indent=2),
        )

    ws3 = str(step2.get("workflowStateHandle", "") or "")
    if not ws3:
        raise RuntimeError("step2 did not return workflowStateHandle")

    # Step 3: get seed + mfaDeviceId
    payload_get_seed = {
        "stepId": "get-totp-registration-credential",
        "workflowStateHandle": ws3,
        "actionId": "SUBMIT",
        "inputs": [
            {
                "input_type": "TOTPRegistrationRequestInput",
                "mfaType": "TOTP",
            },
            {"input_type": "UserRequestInput", "username": ctx.username},
            {
                "input_type": "FingerPrintRequestInput",
                "fingerPrint": ctx.fingerprint,
            },
        ],
        "visitorId": ctx.visitor_id,
        "requestId": str(uuid.uuid4()),
    }
    step3 = post_register(session, ctx, payload_get_seed, args.timeout)
    if args.verbose:
        print(
            "[step3/get-totp-registration-credential seed]",
            json.dumps(step3, ensure_ascii=False, indent=2),
        )

    ws4 = str(step3.get("workflowStateHandle", "") or "")
    if not ws4:
        raise RuntimeError("step3 did not return workflowStateHandle")

    cfg = (
        step3.get("workflowResponseData", {}) or {}
    ).get("totpRegistrationConfigurationResponse", {}) or {}
    mfa_device_id = str(cfg.get("mfaDeviceId", "") or "")
    seed = str(args.seed or cfg.get("totpRegistrationRequestSeed", "") or "")
    if not mfa_device_id:
        raise RuntimeError("step3 did not return mfaDeviceId")
    if not seed and not args.totp_code:
        raise RuntimeError("no seed available; provide --seed or --totp-code")

    # Step 4: submit TOTP code
    if args.totp_code:
        code = args.totp_code.strip()
    else:
        code = pyotp.TOTP(seed).now()

    payload_submit = {
        "stepId": "get-totp-registration-credential",
        "workflowStateHandle": ws4,
        "actionId": "SUBMIT",
        "inputs": [
            {
                "input_type": "TOTPRegistrationRequestInput",
                "totpRegistrationResponseCode": code,
                "mfaDeviceId": mfa_device_id,
                "mfaType": "TOTP",
            },
            {"input_type": "UserRequestInput", "username": ctx.username},
            {
                "input_type": "FingerPrintRequestInput",
                "fingerPrint": ctx.fingerprint,
            },
        ],
        "visitorId": ctx.visitor_id,
        "requestId": str(uuid.uuid4()),
    }
    step4 = post_register(session, ctx, payload_submit, args.timeout)
    print(json.dumps(step4, ensure_ascii=False, indent=2))

    if str(step4.get("stepId", "")).lower() == "handle-registration-failure":
        msg = (step4.get("messagingContext", {}) or {}).get("messageCode")
        raise RuntimeError(f"MFA registration failed: {msg or 'unknown_error'}")


if __name__ == "__main__":
    main()
