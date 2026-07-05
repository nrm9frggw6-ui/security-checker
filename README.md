# 無料セキュリティ診断ツール（MVP）

ドメインを入力するだけで、外部から見える公開情報のみをチェックし
危険度スコアを表示する無料診断ツール。リード獲得の入口として設計。

## 構成

- `main.py` — バックエンドAPI（FastAPI）。実際のスキャン処理を行う。
- `index.html` — フロントエンド。これ単体でブラウザから開ける。
- `test_score.py` — スコア計算ロジックの単体テスト。

## セットアップ（ローカルで動かす場合）

```bash
pip install fastapi uvicorn dnspython requests pydantic
uvicorn main:app --reload --port 8000
```

別ターミナルか、ブラウザで `index.html` を直接開く
（`file://` で開いても、API_BASE が localhost:8000 を向いているので動作する）。

## 動作確認

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## チェック項目

1. **SSL証明書** — 有効性と残り日数
2. **SPF/DMARC** — なりすましメール対策の設定有無
3. **セキュリティヘッダー** — HSTS, X-Frame-Options等の欠落チェック
4. **情報漏洩チェック** — 現在はプレースホルダー。本番では以下のAPIに接続する:
   - XposedOrNot API（無料枠あり）: https://xposedornot.com/api_doc
   - Have I Been Pwned API（有料化済み、要検討）

## 本番デプロイへの道筋

1. **ホスティング**: バックエンドは Railway / Render の無料〜安価プランで十分動く
2. **フロントエンド**: Vercel / Netlify に `index.html` をそのまま置く
   （`API_BASE` を本番のバックエンドURLに変更すること）
3. **メール送信**: `unlockReport()` 内のプレースホルダーを実装する
   - SendGrid / Resend などのAPIでメール送信
   - リード情報（email, domain, score）をDBに保存（Supabase推奨）
4. **CORS**: `main.py` の `allow_origins=["*"]` を、本番のフロントエンドの
   ドメインに絞ること（セキュリティ診断ツール自身がCORS全開放だと格好がつかない）

## 既知の制約・今後の課題

- 漏洩チェックは外部APIの選定と契約が必要（現在はモック）
- スコアリングのロジックは初期版。実際の顧客の反応を見て重みを調整する想定
- レート制限なし。本番では同一IPからの連続スキャンを制限すべき
  （他社サイトへの過剰なスキャンを防ぐため）
- 本ツールはパッシブスキャンのみで、対象サーバーに負荷をかける操作は行わない設計
