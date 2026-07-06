"""
無料セキュリティ診断ツール - バックエンドAPI（メール送信対応版）
"""

import re
import os
import socket
import ssl
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import dns.resolver
import resend
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

app = FastAPI(title="SecScan API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

resend.api_key = os.environ.get("RESEND_API_KEY", "")

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


class LeadRequest(BaseModel):
    email: str
    domain: str
    score: int
    results: list


def check_ssl_certificate(domain: str) -> dict:
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
        return {"check": "ssl_certificate", "status": status, "message": message}
    except Exception:
        return {"check": "ssl_certificate", "status": "fail", "message": "SSL証明書を確認できませんでした"}


def check_spf_dmarc(domain: str) -> dict:
    results = {}
    try:
        spf_found = any(
            b"".join(r.strings).decode(errors="ignore").startswith("v=spf1")
            for r in dns.resolver.resolve(domain, "TXT", lifetime=5)
        )
        results["spf"] = spf_found
    except Exception:
        results["spf"] = False
    try:
        dmarc_found = any(
            b"".join(r.strings).decode(errors="ignore").startswith("v=DMARC1")
            for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        )
        results["dmarc"] = dmarc_found
    except Exception:
        results["dmarc"] = False

    if results["spf"] and results["dmarc"]:
        status, message = "pass", "SPF・DMARCともに設定されています"
    elif results["spf"] or results["dmarc"]:
        status, message = "warn", "SPF・DMARCの一方が未設定です"
    else:
        status, message = "fail", "SPF・DMARCが未設定です（なりすましメールのリスクが高い）"
    return {"check": "spf_dmarc", "status": status, "message": message}


def check_security_headers(domain: str) -> dict:
    important = ["strict-transport-security", "x-content-type-options", "x-frame-options", "content-security-policy"]
    try:
        resp = requests.get(f"https://{domain}", timeout=8, allow_redirects=True)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        missing = [h for h in important if h not in headers_lower]
        if not missing:
            status, message = "pass", "主要なセキュリティヘッダーが設定されています"
        elif len(missing) <= 1:
            status, message = "warn", f"{len(missing)}個のセキュリティヘッダーが未設定です"
        else:
            status, message = "fail", f"{len(missing)}個のセキュリティヘッダーが未設定です"
        return {"check": "security_headers", "status": status, "message": message}
    except Exception:
        return {"check": "security_headers", "status": "fail", "message": "接続できませんでした"}


def check_breach_exposure(domain: str) -> dict:
    return {"check": "breach_exposure", "status": "unknown", "message": "詳細レポートでお届けします", "locked": True}


STATUS_SCORE = {"pass": 25, "warn": 10, "fail": 0, "unknown": 15}


def calculate_score(results):
    scorable = [r for r in results if r["status"] in STATUS_SCORE]
    if not scorable:
        return 0
    return round(sum(STATUS_SCORE[r["status"]] for r in scorable) / (len(scorable) * 25) * 100)


def build_email_html(domain, score, results):
    color = "#2a7a3b" if score >= 70 else "#a26b0c" if score >= 40 else "#b3302f"
    icons = {"pass": "✅", "warn": "⚠️", "fail": "❌", "unknown": "🔒"}
    labels = {"ssl_certificate": "SSL証明書", "spf_dmarc": "なりすましメール対策（SPF/DMARC）",
               "security_headers": "セキュリティヘッダー", "breach_exposure": "情報漏洩チェック"}
    rows = "".join(
        f"<tr><td style='padding:8px'>{icons.get(r['status'],'?')}</td>"
        f"<td style='padding:8px;font-weight:500'>{labels.get(r['check'],r['check'])}</td>"
        f"<td style='padding:8px;color:#555'>{r['message']}</td></tr>"
        for r in results if not r.get("locked")
    )
    return f"""<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px">
  <h1 style="font-size:20px">SecScan 診断レポート</h1>
  <p style="color:#888;font-size:13px">診断ドメイン: {domain}</p>
  <div style="text-align:center;padding:24px;background:#f7f6f3;border-radius:12px;margin:24px 0">
    <div style="font-size:48px;font-weight:600;color:{color}">{score}</div>
    <div style="font-size:13px;color:#888">危険度スコア（100点満点・低いほど危険）</div>
  </div>
  <table style="width:100%;border-collapse:collapse">{rows}</table>
  <div style="background:#fff3cd;border-radius:8px;padding:16px;margin-top:24px">
    <p style="font-size:14px;margin:0;line-height:1.7">⚠️ スコアが低い場合、サイバー攻撃や情報漏洩のリスクが高まっています。対策については専門家への相談をおすすめします。</p>
  </div>
  <p style="font-size:12px;color:#aaa;text-align:center;margin-top:24px">SecScan | <a href="https://secscan-jp.netlify.app" style="color:#aaa">secscan-jp.netlify.app</a></p>
</div>"""


@app.post("/scan")
def scan_domain(req: ScanRequest):
    checks = [check_ssl_certificate, check_spf_dmarc, check_security_headers, check_breach_exposure]
    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        for future in as_completed({executor.submit(fn, req.domain): fn for fn in checks}):
            results.append(future.result())
    return {"domain": req.domain, "score": calculate_score(results), "results": results,
            "scanned_at": datetime.datetime.utcnow().isoformat()}


@app.post("/lead")
def register_lead(req: LeadRequest):
    if not resend.api_key:
        raise HTTPException(status_code=500, detail="メール設定が未完了です")
    try:
        resend.Emails.send({
            "from": "SecScan <onboarding@resend.dev>",
            "to": req.email,
            "subject": f"【SecScan】{req.domain} の診断レポート（スコア: {req.score}点）",
            "html": build_email_html(req.domain, req.score, req.results),
        })
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health():
    return {"status": "ok"}
