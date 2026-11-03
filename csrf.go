package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"sync"
)

// このファイルは CSRF(クロスサイトリクエストフォージェリ)を体験するための「意図的に脆弱な」実装を含む。
// 状態を変更する POST に、CSRFトークン・Origin 検証・再認証のいずれも入れていない(VULNERABLE)。
// Cookie が付いていれば「本人の操作」とみなしてしまう点が問題。

const csrfCookieName = "csrf_session"

// ログイン済みセッション(トークン -> ユーザー名)。メモリ上のみで保持する。
var (
	csrfSessionsMu sync.Mutex
	csrfSessions   = map[string]string{}
)

type Balance struct {
	Username string
	Amount   int
}

func csrfCurrentUser(r *http.Request) string {
	c, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	csrfSessionsMu.Lock()
	defer csrfSessionsMu.Unlock()
	return csrfSessions[c.Value]
}

const csrfLoginTitle = "CSRF: ログイン"

// csrfLoginPageHandler はログインフォームを表示する。ログイン済みならアカウント画面へ移す。
func csrfLoginPageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if csrfCurrentUser(r) != "" {
			http.Redirect(w, r, "/csrf/account", http.StatusSeeOther)
			return
		}
		render(w, "csrf_login.html", map[string]any{"Title": csrfLoginTitle})
	}
}

// csrfLoginPostHandler はログインを処理する。失敗時はフォームを再表示する。
func csrfLoginPostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// このログイン処理自体はプレースホルダを使っており、SQLインジェクションは起きない。
		var n int
		err := db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE username = ? AND password = ?`,
			username, password).Scan(&n)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if n == 0 {
			render(w, "csrf_login.html", map[string]any{"Title": csrfLoginTitle, "Failed": true})
			return
		}

		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		token := hex.EncodeToString(buf)
		csrfSessionsMu.Lock()
		csrfSessions[token] = username
		csrfSessionsMu.Unlock()

		// VULNERABLE: SameSite 属性を指定していない。また CSRFトークンも発行していない。
		// SameSite=Strict を付けるか、フォームにトークンを埋め込んで検証するのが本来の対策。
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
		})
		http.Redirect(w, r, "/csrf/account", http.StatusSeeOther)
	}
}

func csrfAccountHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := csrfCurrentUser(r)
		if user == "" {
			http.Redirect(w, r, "/csrf/login", http.StatusSeeOther)
			return
		}

		rows, err := db.Query(`SELECT username, balance FROM csrf_balances ORDER BY username`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var balances []Balance
		var mine int
		for rows.Next() {
			var b Balance
			if err := rows.Scan(&b.Username, &b.Amount); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if b.Username == user {
				mine = b.Amount
			}
			balances = append(balances, b)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := map[string]any{
			"Title":    "CSRF: アカウント",
			"User":     user,
			"Balance":  mine,
			"Balances": balances,
			"Msg":      r.URL.Query().Get("msg"),
		}
		render(w, "csrf_account.html", data)
	}
}

func csrfLogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(csrfCookieName); err == nil {
			csrfSessionsMu.Lock()
			delete(csrfSessions, c.Value)
			csrfSessionsMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/csrf/login", http.StatusSeeOther)
	}
}

func csrfPasswordHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// VULNERABLE: Cookie でログイン中と分かれば実行する。リクエストが本当にこのサイトの
		// フォームから送られたものか(CSRFトークン / Origin / Referer)を確認していない。
		user := csrfCurrentUser(r)
		if user == "" {
			http.Error(w, "ログインしてください", http.StatusUnauthorized)
			return
		}
		newPassword := r.FormValue("new_password")
		if newPassword == "" {
			http.Error(w, "新しいパスワードは必須です", http.StatusBadRequest)
			return
		}
		// 現在のパスワードの再入力も求めていない(再認証があれば攻撃者は実行できない)。
		if _, err := db.Exec(`UPDATE accounts SET password = ? WHERE username = ?`, newPassword, user); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/csrf/account?msg=パスワードを変更しました", http.StatusSeeOther)
	}
}

func csrfTransferHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// VULNERABLE: パスワード変更と同様、リクエストの出所を確認していない。
		user := csrfCurrentUser(r)
		if user == "" {
			http.Error(w, "ログインしてください", http.StatusUnauthorized)
			return
		}
		to := r.FormValue("to")
		amount, err := strconv.Atoi(r.FormValue("amount"))
		if err != nil || amount <= 0 {
			http.Error(w, "金額が不正です", http.StatusBadRequest)
			return
		}

		tx, err := db.Begin()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		var balance int
		if err := tx.QueryRow(`SELECT balance FROM csrf_balances WHERE username = ?`, user).Scan(&balance); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if balance < amount {
			http.Error(w, "残高が不足しています", http.StatusBadRequest)
			return
		}
		res, err := tx.Exec(`UPDATE csrf_balances SET balance = balance + ? WHERE username = ?`, amount, to)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			http.Error(w, "送金先が存在しません", http.StatusBadRequest)
			return
		}
		if _, err := tx.Exec(`UPDATE csrf_balances SET balance = balance - ? WHERE username = ?`, amount, user); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tx.Commit(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/csrf/account?msg="+strconv.Itoa(amount)+"円を送金しました", http.StatusSeeOther)
	}
}

// csrfResetHandler は残高とパスワードを初期状態に戻す(学習環境の復旧用)。
// SQLインジェクション画面のアカウントのパスワードも元に戻る。
func csrfResetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stmts := []string{
			`DELETE FROM csrf_balances WHERE TRUE`,
			`UPDATE accounts SET password = 'S3cr3t-Adm1n!' WHERE username = 'admin'`,
			`UPDATE accounts SET password = 'password1' WHERE username = 'alice'`,
			`UPDATE accounts SET password = 'qwerty' WHERE username = 'bob'`,
		}
		for _, s := range stmts {
			if _, err := db.Exec(s); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if err := initCSRFBalances(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/csrf/account?msg=初期状態に戻しました", http.StatusSeeOther)
	}
}

// registerCSRFRoutes は CSRF 関連のルートを登録する。罠ページは別モジュール trap/ にあり、別プロセスで起動する。
func registerCSRFRoutes(mux *http.ServeMux) {
	mux.Handle("GET /csrf/login", csrfLoginPageHandler())
	mux.Handle("POST /csrf/login", csrfLoginPostHandler())
	mux.Handle("GET /csrf/account", csrfAccountHandler())
	mux.Handle("POST /csrf/logout", csrfLogoutHandler())
	mux.Handle("POST /csrf/password", csrfPasswordHandler())
	mux.Handle("POST /csrf/transfer", csrfTransferHandler())
	mux.Handle("POST /csrf/reset", csrfResetHandler())
}
