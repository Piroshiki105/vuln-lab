package main

import (
	"net/http"
	"sync"
)

// このファイルはクリックジャッキングを体験するための「意図的に脆弱な」実装を含む。
// 重要操作(プロフィール公開)のボタンがあるページを、X-Frame-Options も
// Content-Security-Policy: frame-ancestors も付けずに返している(VULNERABLE)。
// そのため、攻撃者のページが透明な iframe でこのページを重ね、被害者に
// 別のボタンだと思わせてクリックさせられる。
// ログインは CSRF 画面と共通のセッション(csrf_session)を使い、ログイン画面だけ表示を分けている。

// プロフィール公開状態(ユーザー名 -> 公開中か)。メモリ上のみで保持する。
var (
	clickjackMu     sync.Mutex
	clickjackPublic = map[string]bool{}
)

var clickjackLoginConfig = loginConfig{
	Title:  "クリックジャッキング: ログイン",
	Intro:  "クリックジャッキングを体験するため、まずログインします。ログイン状態は CSRF 画面と共通で、SQLインジェクションの画面と同じアカウントを使えます(例: alice / password1)。",
	Action: "/clickjack/login",
	Next:   "/clickjack/settings",
	IPA:    "1.9",
}

func clickjackSettingsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := csrfCurrentUser(r)
		if user == "" {
			http.Redirect(w, r, "/clickjack/login", http.StatusSeeOther)
			return
		}
		clickjackMu.Lock()
		public := clickjackPublic[user]
		clickjackMu.Unlock()

		// VULNERABLE: X-Frame-Options / frame-ancestors を設定していない。
		// 本来は w.Header().Set("X-Frame-Options", "DENY") と
		// w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'") を付ける。
		render(w, r, "clickjack_settings.html", map[string]any{
			"Title":  "クリックジャッキング: 設定",
			"User":   user,
			"Public": public,
		})
	}
}

func clickjackPublishHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := csrfCurrentUser(r)
		if user == "" {
			http.Error(w, "ログインしてください", http.StatusUnauthorized)
			return
		}
		// この操作自体は、利用者がこのページのボタンを実際にクリックしたもの。
		// CSRFトークンがあってもクリックジャッキングは防げない点が CSRF との違い。
		clickjackMu.Lock()
		clickjackPublic[user] = true
		clickjackMu.Unlock()
		http.Redirect(w, r, "/clickjack/settings", http.StatusSeeOther)
	}
}

// clickjackResetHandler は公開状態を非公開に戻す(学習環境の復旧用)。
func clickjackResetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clickjackMu.Lock()
		clickjackPublic = map[string]bool{}
		clickjackMu.Unlock()
		http.Redirect(w, r, "/clickjack/settings", http.StatusSeeOther)
	}
}

// registerClickjackRoutes はクリックジャッキング関連のルートを登録する。罠ページは別モジュール trap/ にある。
func registerClickjackRoutes(mux *http.ServeMux) {
	mux.Handle("GET /clickjack/login", loginPageHandler(clickjackLoginConfig))
	mux.Handle("POST /clickjack/login", loginPostHandler(clickjackLoginConfig))
	mux.Handle("GET /clickjack/settings", clickjackSettingsHandler())
	mux.Handle("POST /clickjack/publish", clickjackPublishHandler())
	mux.Handle("POST /clickjack/reset", clickjackResetHandler())
}
