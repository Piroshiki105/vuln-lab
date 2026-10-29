package main

import (
	"database/sql"
	"html/template"
	"net/http"
)

// このファイルは XSS(クロスサイトスクリプティング)を体験するための「意図的に脆弱な」実装を含む。
// html/template は通常自動でエスケープするが、template.HTML 型に変換した値はエスケープされない。
// その型変換(VULNERABLE)を、学習のためにわざと行っている。

type Comment struct {
	ID        int
	Name      template.HTML
	Body      template.HTML
	CreatedAt string
}

func initXSSDB(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS comments (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		name       TEXT NOT NULL,
		body       TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return err
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM comments`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := db.Exec(`INSERT INTO comments (name, body) VALUES
			('山田', 'はじめまして。掲示板のテスト投稿です。'),
			('佐藤', 'よろしくお願いします!')`); err != nil {
			return err
		}
	}
	return nil
}

// setDemoCookie は XSS で盗み出す対象となる、デモ用のセッションCookieを発行する。
// VULNERABLE: HttpOnly を付けていないため、JavaScript の document.cookie から読み取れる。
func setDemoCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:  "demo_session",
		Value: "secret-session-token-12345",
		Path:  "/",
		// HttpOnly: true を付ければ JavaScript から読めなくなる(対策の一つ)。
	})
}

func xssReflectedHandler(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setDemoCookie(w)
		data := map[string]any{"Title": "XSS: 反射型"}

		if q, ok := r.URL.Query()["q"]; ok && len(q) > 0 {
			// VULNERABLE: 入力値を template.HTML に変換し、エスケープを無効化している。
			// 本来は string のままテンプレートに渡し、自動エスケープに任せる。
			data["Q"] = template.HTML(q[0])
			data["Searched"] = true
		}

		render(w, tmpl, "xss_reflected.html", data)
	}
}

func xssBoardHandler(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setDemoCookie(w)

		rows, err := db.Query(`SELECT id, name, body, created_at FROM comments ORDER BY id`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var comments []Comment
		for rows.Next() {
			var id int
			var name, body, createdAt string
			if err := rows.Scan(&id, &name, &body, &createdAt); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// VULNERABLE: 保存された投稿を template.HTML に変換し、エスケープせず出力している。
			// 投稿に含まれたスクリプトが、ページを開いた全員のブラウザで実行される(格納型XSS)。
			comments = append(comments, Comment{id, template.HTML(name), template.HTML(body), createdAt})
		}
		if err := rows.Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := map[string]any{"Title": "XSS: 格納型(掲示板)", "Comments": comments}
		render(w, tmpl, "xss_board.html", data)
	}
}

func xssBoardPostHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("name")
		body := r.FormValue("body")
		if name == "" || body == "" {
			http.Error(w, "名前と本文は必須です", http.StatusBadRequest)
			return
		}
		// 保存時のSQLはプレースホルダを使っており、SQLインジェクションは起きない。
		// 問題は「保存した値を出力時にエスケープしていない」点にある。
		if _, err := db.Exec(`INSERT INTO comments (name, body) VALUES (?, ?)`, name, body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/xss/board", http.StatusSeeOther)
	}
}

// xssBoardResetHandler は掲示板を初期状態に戻す。
// 悪意ある投稿でページが操作不能になった場合の復旧用(学習環境の利便のため)。
func xssBoardResetHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := db.Exec(`DELETE FROM comments`); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := initXSSDB(db); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/xss/board", http.StatusSeeOther)
	}
}

// registerXSSRoutes は XSS(反射型・格納型)関連のルートを登録する。
func registerXSSRoutes(mux *http.ServeMux, db *sql.DB) error {
	if err := initXSSDB(db); err != nil {
		return err
	}
	reflectedTmpl := parseTemplate("xss_reflected.html")
	boardTmpl := parseTemplate("xss_board.html")
	mux.Handle("GET /xss/reflected", xssReflectedHandler(reflectedTmpl))
	mux.Handle("GET /xss/board", xssBoardHandler(db, boardTmpl))
	mux.Handle("POST /xss/board", xssBoardPostHandler(db))
	mux.Handle("POST /xss/board/reset", xssBoardResetHandler(db))
	return nil
}
