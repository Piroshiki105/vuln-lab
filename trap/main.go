package main

import (
	"html"
	"log"
	"net/http"
	"strings"
)

// このファイルは罠サーバー(攻撃者サイトを模したもの)の入口。
// 本体(8080)とは別ポート(9090)で起動し、別オリジンから本体へリクエストを送らせる。
// 127.0.0.1 の別ポートは「同一サイト」扱いのため、SameSite=Lax 既定のブラウザでも Cookie が送られる。
// 本体と同様、127.0.0.1 にのみバインドする。
// 攻撃の種類ごとのページは csrf_trap.go(CSRF)と xss_trap.go(反射型XSS)にある。

const trapListenAddr = "127.0.0.1:9090"

// trapIndexHTML は罠サーバーのトップ。攻撃の種類(CSRF / XSS)ごとに第1階層で分けている。
const trapIndexHTML = `<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>罠ページ - vuln-lab</title></head>
<body>
<div style="background:#b00020;color:#fff;padding:8px 16px;font-weight:bold">⚠️ 攻撃者サイトを模した罠ページです(ローカル学習専用)</div>
<h1>攻撃者サイト(罠ページ集)</h1>
<ul>
  <li><a href="/csrf/">CSRF の罠</a>(ログイン中の被害者に、勝手に送金・パスワード変更をさせる)</li>
  <li><a href="/xss/">反射型XSS の罠</a>(リンクを踏ませ、標的サイト上でスクリプトを実行させCookieを盗む)</li>
  <li><a href="/clickjack/">クリックジャッキングの罠</a>(透明な iframe を重ね、別のボタンだと思わせて押させる)</li>
  <li><a href="/session/">セッションIDの固定化の罠</a>(攻撃者が決めたセッションIDを被害者に押し付ける)</li>
  <li><a href="/xss/loot">XSS の戦利品</a>(盗み出したCookieの一覧。攻撃者側の画面)</li>
</ul>
</body></html>`

func trapPage(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(body))
	}
}

// withNote は罠ページの <body> の直後に「このページがしていること」の帯を差し込む。
// 罠ページがどのように攻撃しているかを、被害者役(学習者)が読めるようにするためのもの。
func withNote(page, what string) string {
	i := strings.Index(page, "<body")
	if i < 0 {
		return page
	}
	j := strings.Index(page[i:], ">")
	if j < 0 {
		return page
	}
	note := `<div style="background:#fff3cd;border:1px solid #c9a400;padding:8px 16px;margin:8px"><strong>このページがしていること:</strong> ` +
		html.EscapeString(what) + `</div>`
	k := i + j + 1
	return page[:k] + note + page[k:]
}

func main() {
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", trapPage(trapIndexHTML))
	registerCSRFTrapRoutes(mux)
	registerXSSTrapRoutes(mux)
	registerClickjackTrapRoutes(mux)
	registerSessionTrapRoutes(mux)

	log.Printf("trap server listening on http://%s", trapListenAddr)
	log.Println(http.ListenAndServe(trapListenAddr, mux))
}
