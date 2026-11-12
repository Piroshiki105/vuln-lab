package main

import (
	"html/template"
	"net/http"
	"time"
)

// このファイルは XSS(クロスサイトスクリプティング)を体験するための「意図的に脆弱な」実装を含む。
// html/template は通常自動でエスケープするが、template.HTML 型に変換した値はエスケープされない。
// その型変換(VULNERABLE)を、学習のためにわざと行っている。

type Comment struct {
	ID        string
	Name      template.HTML
	Body      template.HTML
	CreatedAt string
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

func xssReflectedHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setDemoCookie(w)
		data := map[string]any{"Title": "XSS: 反射型"}

		if q, ok := r.URL.Query()["q"]; ok && len(q) > 0 {
			// VULNERABLE: 入力値を template.HTML に変換し、エスケープを無効化している。
			// 本来は string のままテンプレートに渡し、自動エスケープに任せる。
			data["Q"] = template.HTML(q[0])
			data["Searched"] = true
		}

		render(w, r, "xss_reflected.html", data)
	}
}

func xssBoardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setDemoCookie(w)

		rows, err := db.Query(`SELECT id, name, body, created_at FROM comments ORDER BY created_at, id`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var comments []Comment
		for rows.Next() {
			var id, name, body string
			var createdAt time.Time
			if err := rows.Scan(&id, &name, &body, &createdAt); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// VULNERABLE: 保存された投稿を template.HTML に変換し、エスケープせず出力している。
			// 投稿に含まれたスクリプトが、ページを開いた全員のブラウザで実行される(格納型XSS)。
			comments = append(comments, Comment{id, template.HTML(name), template.HTML(body), createdAt.Format("2006-01-02 15:04:05")})
		}
		if err := rows.Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := map[string]any{"Title": "XSS: 格納型(掲示板)", "Comments": comments}
		render(w, r, "xss_board.html", data)
	}
}

func xssBoardPostHandler() http.HandlerFunc {
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
func xssBoardResetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := db.Exec(`DELETE FROM comments WHERE TRUE`); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := initComments(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/xss/board", http.StatusSeeOther)
	}
}

// registerXSSRoutes は XSS(反射型・格納型)関連のルートを登録する。
func registerXSSRoutes(mux *http.ServeMux) {
	mux.Handle("GET /xss/reflected", xssReflectedHandler())
	mux.Handle("GET /xss/board", xssBoardHandler())
	mux.Handle("POST /xss/board", xssBoardPostHandler())
	mux.Handle("POST /xss/board/reset", xssBoardResetHandler())
}
