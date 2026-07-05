"""
無料セキュリティ診断ツール - バックエンドAPI

公開情報のみをチェックするパッシブスキャン。
対象サーバーへの侵入的な操作は一切行わない。

必要なライブラリ:
    pip install fastapi uvicorn dnspython requests

起動方法:
    uvicorn main:app --reload --port 8000

エンドポイント:
    POST /scan  { "domain": "example.co.jp" }
"""

import re
import socket
import ssl
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import dns.resolver
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

app = FastAPI(title="Domain Security Checker")

# フロントエンドから呼べるようにCORSを許可（本番では allow_origins を絞ること）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


class ScanRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v: str) -> str:
        v = v.strip().lower()
        v = re.sub(r"^https?://", "", v)
        v = v.split("/")[0]
        if not DOMAIN_PATTERN.match(v):
            raise ValueError("ドメイン形式が正しくありません")
        return v


# ---------------------------------------------------------------------------
# 各チェック関数
# それぞれ独立して失敗してよい（1項目落ちても他の結果は返す）
# ---------------------------------------------------------------------------

def check_ssl_certificate(domain: str) -> dict:
    """SSL証明書の有効性と残り日数をチェック"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        expire_str = cert["notAfter"]
        expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_date - datetime.datetime.utcnow()).days

        if days_left < 0:
            status, message = "fail", "SSL証明書の期限が切れています"
        elif days_left < 14:
            status, message = "warn", f"SSL証明書の期限が{days_left}日後に切れます"
        else:
            status, message = "pass", f"SSL証明書は有効です（残り{days_left}日）"

        return {"check": "ssl_certificate", "status": status, "message": message, "days_left": days_left}
    except Exception as e:
        return {"check": "ssl_certificate", "status": "fail", "message": f"SSL証明書を確認できませんでした（{type(e).__name__}）"}


def check_spf_dmarc(domain: str) -> dict:
    """SPF/DMARCレコードの有無をチェック（なりすましメール対策）"""
    results = {}
    try:
        spf_found = False
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.startswith("v=spf1"):
                spf_found = True
        results["spf"] = spf_found
    except Exception:
        results["spf"] = False

    try:
        dmarc_found = False
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.startswith("v=DMARC1"):
                dmarc_found = True
        results["dmarc"] = dmarc_found
    except Exception:
        results["dmarc"] = False

    if results["spf"] and results["dmarc"]:
        status, message = "pass", "SPF・DMARCともに設定されています"
    elif results["spf"] or results["dmarc"]:
        status, message = "warn", "SPF・DMARCの一方が未設定です（なりすましメールのリスク）"
    else:
        status, message = "fail", "SPF・DMARCが未設定です（なりすましメールのリスクが高い）"

    return {"check": "spf_dmarc", "status": status, "message": message, "detail": results}


def check_security_headers(domain: str) -> dict:
    """重要なセキュリティヘッダーの有無をチェック"""
    important_headers = [
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
    ]
    try:
        resp = requests.get(f"https://{domain}", timeout=8, allow_redirects=True)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        missing = [h for h in important_headers if h not in headers_lower]

        if not missing:
            status, message = "pass", "主要なセキュリティヘッダーが設定されています"
        elif len(missing) <= 1:
            status, message = "warn", f"{len(missing)}個のセキュリティヘッダーが未設定です"
        else:
            status, message = "fail", f"{len(missing)}個のセキュリティヘッダーが未設定です"

        return {
            "check": "security_headers",
            "status": status,
            "message": message,
            "missing": missing,
            "server_header": headers_lower.get("server", "不明"),
        }
    except Exception as e:
        return {"check": "security_headers", "status": "fail", "message": f"接続できませんでした（{type(e).__name__}）"}


def check_breach_exposure(domain: str) -> dict:
    """
    ドメインに紐づくメールアドレスの漏洩履歴をチェック。
    本番では Have I Been Pwned API (要APIキー、有料化済み) や
    XposedOrNot API (無料枠あり) を利用する。
    ここではプレースホルダー実装。
    """
    # NOTE: 実際にはここで外部APIを呼ぶ。例:
    # resp = requests.get(f"https://api.xposedornot.com/v1/check-domain/{domain}")
    return {
        "check": "breach_exposure",
        "status": "unknown",
        "message": "この項目は詳細レポート（メール登録後）でお届けします",
        "locked": True,
    }


# ---------------------------------------------------------------------------
# スコアリング
# ---------------------------------------------------------------------------

STATUS_SCORE = {"pass": 25, "warn": 10, "fail": 0, "unknown": 15}


def calculate_score(results: list[dict]) -> int:
    scorable = [r for r in results if r["status"] in STATUS_SCORE]
    if not scorable:
        return 0
    total = sum(STATUS_SCORE[r["status"]] for r in scorable)
    max_total = len(scorable) * 25
    return round(total / max_total * 100)


@app.post("/scan")
def scan_domain(req: ScanRequest):
    domain = req.domain

    # 4項目を並列実行（直列だと合計で15秒以上かかる）
    checks = [check_ssl_certificate, check_spf_dmarc, check_security_headers, check_breach_exposure]
    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fn, domain): fn for fn in checks}
        for future in as_completed(futures):
            results.append(future.result())

    score = calculate_score(results)
    fail_count = sum(1 for r in results if r["status"] == "fail")

    return {
        "domain": domain,
        "score": score,
        "fail_count": fail_count,
        "results": results,
        "scanned_at": datetime.datetime.utcnow().isoformat(),
    }


@app.get("/health")
def health():
    return {"status": "ok"}
