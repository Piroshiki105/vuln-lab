package main

import (
	"net/http"
	"strconv"
	"strings"
)

// このファイルはアクセス制御・認可制御の欠落(IPA 1.11)を体験するための
// 「意図的に脆弱な」実装を含む。
//   - 11-(i) アクセス制御の欠落: メールアドレスだけでログインできる(パスワード不要)。
//   - 11-(ii) 認可制御の欠落: URL の id をそのまま使い、ログイン中の本人の id か確認しない(IDOR)。
//   - 管理画面: URL を知っていれば、管理者でなくても開いて操作できる(強制ブラウジング)。
// セッションは CSRF 画面と共通(csrf_session)。メールアドレスは `ユーザー名@example.com` の形で導出する。

const authzMailDomain = "example.com"

var authzLoginConfig = loginConfig{
	Title:  "アクセス制御の欠落: ログイン",
	Intro:  "メールアドレスだけでログインできます(パスワードは不要)。メールアドレスは「ユーザー名@" + authzMailDomain + "」の形です。ユーザー名は SQLインジェクション画面と同じ(admin / alice / bob)です。",
	Action: "/authz/login",
	Next:   "/authz/profile",
	IPA:    "1.11",
}

type authzAccount struct {
	ID       int
	Username string
	Email    string
	Role     string
	Balance  int
}

func authzEmail(username string) string { return username + "@" + authzMailDomain }

// authzLoadAccount は id のアカウント情報と残高を読む。存在しなければ ok=false。
func authzLoadAccount(id int) (a authzAccount, ok bool, err error) {
	rows, err := db.Query(`SELECT a.id, a.username, a.role, COALESCE(b.balance, 0)
		FROM accounts a LEFT JOIN csrf_balances b ON b.username = a.username WHERE a.id = ?`, id)
	if err != nil {
		return a, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return a, false, rows.Err()
	}
	if err := rows.Scan(&a.ID, &a.Username, &a.Role, &a.Balance); err != nil {
		return a, false, err
	}
	a.Email = authzEmail(a.Username)
	return a, true, nil
}

func authzIDByUsername(username string) (int, error) {
	var id int
	err := db.QueryRow(`SELECT id FROM accounts WHERE username = ?`, username).Scan(&id)
	return id, err
}

// authzLoginPostHandler はメールアドレスだけでログインさせる。
func authzLoginPostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := strings.TrimSpace(r.FormValue("email"))
		// VULNERABLE: メールアドレスは他人にも知られ得る情報で、秘密情報ではない。
		// パスワード等の入力を求めず、メールアドレスの一致だけで本人とみなしている。
		username, domain, found := strings.Cut(email, "@")
		if !found || domain != authzMailDomain {
			render(w, r, "authz_login.html", authzLoginConfig.data(true))
			return
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE username = ?`, username).Scan(&n); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if n == 0 {
			render(w, r, "authz_login.html", authzLoginConfig.data(true))
			return
		}
		if err := csrfStartSession(w, username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authzLoginConfig.Next, http.StatusSeeOther)
	}
}

func authzLoginPageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if csrfCurrentUser(r) != "" {
			http.Redirect(w, r, authzLoginConfig.Next, http.StatusSeeOther)
			return
		}
		render(w, r, "authz_login.html", authzLoginConfig.data(false))
	}
}

// authzProfileHandler は id のアカウントの情報を表示する。id 省略時はログイン中の本人。
func authzProfileHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := csrfCurrentUser(r)
		if user == "" {
			http.Redirect(w, r, "/authz/login", http.StatusSeeOther)
			return
		}
		myID, err := authzIDByUsername(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		id := myID
		if v := r.URL.Query().Get("id"); v != "" {
			if id, err = strconv.Atoi(v); err != nil {
				http.Error(w, "id が不正です", http.StatusBadRequest)
				return
			}
		}
		// VULNERABLE: URL の id をそのまま使っている。ログイン中の利用者の id(myID)と
		// 一致するかを確認していないため、id を書き換えれば他人の情報を閲覧できる。
		// 本来は id を URL から取らずセッションの利用者から決めるか、id == myID を検証する。
		a, ok, err := authzLoadAccount(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "アカウントが存在しません", http.StatusNotFound)
			return
		}
		render(w, r, "authz_profile.html", map[string]any{
			"Title": "アクセス制御の欠落: プロフィール",
			"Other": id != myID,
			"User":  user,
			"MyID":  myID,
			"A":     a,
		})
	}
}

// authzAdminHandler は全アカウントの一覧と権限変更ボタンを表示する。
func authzAdminHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := csrfCurrentUser(r)
		if user == "" {
			http.Redirect(w, r, "/authz/login", http.StatusSeeOther)
			return
		}
		// VULNERABLE: ログインしているかしか見ておらず、管理者(role = 'admin')か確認していない。
		// 管理者向けのリンクを画面に出さないだけでは防げず、URL を知っていれば誰でも開ける(強制ブラウジング)。
		rows, err := db.Query(`SELECT id, username, role FROM accounts ORDER BY id`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var accounts []authzAccount
		for rows.Next() {
			var a authzAccount
			if err := rows.Scan(&a.ID, &a.Username, &a.Role); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			a.Email = authzEmail(a.Username)
			accounts = append(accounts, a)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var myRole string
		if err := db.QueryRow(`SELECT role FROM accounts WHERE username = ?`, user).Scan(&myRole); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		render(w, r, "authz_admin.html", map[string]any{
			"Title":    "アクセス制御の欠落: 管理画面",
			"User":     user,
			"MyRole":   myRole,
			"Accounts": accounts,
		})
	}
}

// authzPromoteHandler は id のアカウントを管理者にする。
func authzPromoteHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if csrfCurrentUser(r) == "" {
			http.Error(w, "ログインしてください", http.StatusUnauthorized)
			return
		}
		id, err := strconv.Atoi(r.FormValue("id"))
		if err != nil {
			http.Error(w, "id が不正です", http.StatusBadRequest)
			return
		}
		// VULNERABLE: 呼び出した利用者が管理者かを確認していない(画面を隠しても直接 POST できる)。
		if _, err := db.Exec(`UPDATE accounts SET role = 'admin' WHERE id = ?`, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/authz/admin", http.StatusSeeOther)
	}
}

// authzResetHandler は権限を初期状態(admin のみ管理者)に戻す(学習環境の復旧用)。
func authzResetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := db.Exec(`UPDATE accounts SET role = 'user' WHERE username IN ('alice', 'bob')`); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/authz/admin", http.StatusSeeOther)
	}
}

// registerAuthzRoutes はアクセス制御・認可制御の欠落に関するルートを登録する。
func registerAuthzRoutes(mux *http.ServeMux) {
	mux.Handle("GET /authz/login", authzLoginPageHandler())
	mux.Handle("POST /authz/login", authzLoginPostHandler())
	mux.Handle("POST /authz/logout", logoutHandler("/authz/login"))
	mux.Handle("GET /authz/profile", authzProfileHandler())
	mux.Handle("GET /authz/admin", authzAdminHandler())
	mux.Handle("POST /authz/admin/promote", authzPromoteHandler())
	mux.Handle("POST /authz/admin/reset", authzResetHandler())
}
