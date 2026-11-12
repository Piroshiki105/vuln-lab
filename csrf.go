package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
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

// loginConfig はログイン画面の表示と遷移先。CSRF 画面とクリックジャッキング画面で
// ログイン処理(セッションは共通)を共有しつつ、画面ごとに説明文と戻り先を変えるためのもの。
type loginConfig struct {
	Title  string // 見出しとページタイトル
	Intro  string // 画面の説明文
	Action string // フォームの送信先(この画面の POST ルート)
	Next   string // ログイン済み・ログイン成功後の遷移先
	IPA    string // 画面に出す IPA 項番
	CWE    string // 画面に出す CWE
}

func (c loginConfig) data(failed bool) map[string]any {
	return map[string]any{"Title": c.Title, "Intro": c.Intro, "Action": c.Action, "Failed": failed, "IPA": c.IPA, "CWE": c.CWE}
}

var csrfLoginConfig = loginConfig{
	Title:  "CSRF: ログイン",
	Intro:  "CSRF を体験するため、まずログインします。SQLインジェクションの画面と同じアカウントを使えます(例: alice / password1)。",
	Action: "/csrf/login",
	Next:   "/csrf/account",
	IPA:    "1.6",
	CWE:    "CWE-352",
}

// loginPageHandler はログインフォームを表示する。ログイン済みなら遷移先へ移す。
func loginPageHandler(cfg loginConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if csrfCurrentUser(r) != "" {
			http.Redirect(w, r, cfg.Next, http.StatusSeeOther)
			return
		}
		render(w, r, "login.html", cfg.data(false))
	}
}

// csrfStartSession はセッションを発行して Cookie に載せる。認証方式が違う画面(authz.go)とも共有する。
func csrfStartSession(w http.ResponseWriter, username string) error {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return err
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
	return nil
}

// loginPostHandler はログインを処理する。失敗時はフォームを再表示する。
func loginPostHandler(cfg loginConfig) http.HandlerFunc {
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
			render(w, r, "login.html", cfg.data(true))
			return
		}

		if err := csrfStartSession(w, username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, cfg.Next, http.StatusSeeOther)
	}
}

// csrfLastReq は直近に受け付けた状態変更リクエストの記録。画面の「内部で何が起きたか」用。
// VULNERABLE な処理が、実際には何を見て(何を見ずに)実行したかを学習者に見せる。
type csrfReqInfo struct {
	Action, Host, Origin, Referer string
	HasCookie                     bool
	Foreign                       bool // Origin / Referer が、このサイト以外を指している
}

var (
	csrfLastMu  sync.Mutex
	csrfLastReq *csrfReqInfo
)

func csrfRecordReq(r *http.Request, action string) {
	info := &csrfReqInfo{Action: action, Host: r.Host, Origin: r.Header.Get("Origin"), Referer: r.Header.Get("Referer")}
	_, err := r.Cookie(csrfCookieName)
	info.HasCookie = err == nil
	own := "http://" + r.Host
	info.Foreign = (info.Origin != "" && info.Origin != own) ||
		(info.Referer != "" && !strings.HasPrefix(info.Referer, own+"/"))
	csrfLastMu.Lock()
	csrfLastReq = info
	csrfLastMu.Unlock()
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
		csrfLastMu.Lock()
		data["LastReq"] = csrfLastReq
		csrfLastMu.Unlock()
		render(w, r, "csrf_account.html", data)
	}
}

// logoutHandler はセッションを破棄し、next へ移す。
func logoutHandler(next string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(csrfCookieName); err == nil {
			csrfSessionsMu.Lock()
			delete(csrfSessions, c.Value)
			csrfSessionsMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, next, http.StatusSeeOther)
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
		csrfRecordReq(r, "パスワード変更")
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
		csrfRecordReq(r, "送金")
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
	mux.Handle("GET /csrf/login", loginPageHandler(csrfLoginConfig))
	mux.Handle("POST /csrf/login", loginPostHandler(csrfLoginConfig))
	mux.Handle("GET /csrf/account", csrfAccountHandler())
	mux.Handle("POST /csrf/logout", logoutHandler("/csrf/login"))
	mux.Handle("POST /csrf/password", csrfPasswordHandler())
	mux.Handle("POST /csrf/transfer", csrfTransferHandler())
	mux.Handle("POST /csrf/reset", csrfResetHandler())
}
