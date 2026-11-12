package main

import (
	"database/sql"
	"net/http"
	"strings"
)

// このファイルは SQLインジェクションを体験するための「意図的に脆弱な」実装を含む。
// SQL文を文字列連結で組み立てている箇所(VULNERABLE)は、学習のためにわざとそうしている。

type LoginResult struct {
	ID       string
	Username string
	Role     string
}

type Product struct {
	ID          string
	Name        string
	Description string
	Price       string
}

// SQL の固定部分。入力値はこの断片の間に連結される。
// 実行するSQLと、画面のプレビュー(入力値の強調表示)で同じ断片を使う。
var (
	loginSQLFixed  = []string{"SELECT id, username, role FROM accounts WHERE username = '", "' AND password = '", "'"}
	searchSQLFixed = []string{"SELECT id, name, description, price FROM products WHERE is_public = 1 AND name LIKE '%", "%'"}
)

// sqlPart は組み立て後のSQLの一部。Input が true の部分は利用者の入力に由来する。
type sqlPart struct {
	Text  string
	Input bool
}

// buildSQL は固定部分 fixed の間に inputs を挟んでSQL文を組み立てる。
// 実行する文字列と、入力由来の部分を強調表示するための断片列を返す。
// VULNERABLE: 入力値をエスケープもバインドもせず、そのまま連結している。
func buildSQL(fixed []string, inputs ...string) (string, []sqlPart) {
	var sb strings.Builder
	var parts []sqlPart
	add := func(text string, input bool) {
		sb.WriteString(text)
		if text != "" {
			parts = append(parts, sqlPart{Text: text, Input: input})
		}
	}
	for i, f := range fixed {
		add(f, false)
		if i < len(inputs) {
			add(inputs[i], true)
		}
	}
	return sb.String(), parts
}

// sqliLoginData はログイン画面の表示に共通で必要な値を返す。
func sqliLoginData() map[string]any {
	return map[string]any{
		"Title":     "SQLインジェクション: ログイン",
		"SQLFixed":  loginSQLFixed,
		"SQLInputs": []string{"username", "password"},
	}
}

// sqliLoginPageHandler はログインフォームを表示する。
func sqliLoginPageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, r, "sqli_login.html", sqliLoginData())
	}
}

// sqliLoginPostHandler はログインを処理し、結果とともにフォームを再表示する。
func sqliLoginPostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := sqliLoginData()
		username := r.FormValue("username")
		password := r.FormValue("password")

		// VULNERABLE: 入力値をそのままSQL文に連結している。
		// 本来は db.QueryRow("... WHERE username = ? AND password = ?", username, password) のように
		// プレースホルダ(バインド変数)を使う。
		query, parts := buildSQL(loginSQLFixed, username, password)

		data["Username"] = username
		data["QueryParts"] = parts

		var res LoginResult
		err := db.QueryRow(query).Scan(&res.ID, &res.Username, &res.Role)
		switch {
		case err == sql.ErrNoRows:
			data["Failed"] = true
		case err != nil:
			// VULNERABLE: DBのエラーメッセージをそのまま画面に出している(情報漏えいの原因)。
			data["Error"] = err.Error()
		default:
			data["Result"] = res
		}

		render(w, r, "sqli_login.html", data)
	}
}

func sqliSearchHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]any{
			"Title":     "SQLインジェクション: 商品検索",
			"SQLFixed":  searchSQLFixed,
			"SQLInputs": []string{"q"},
		}

		if q, ok := r.URL.Query()["q"]; ok && len(q) > 0 {
			// VULNERABLE: 検索語をそのままSQL文に連結している。
			// is_public = 1 で非公開商品を隠しているつもりでも、入力次第で条件を崩せる。
			query, parts := buildSQL(searchSQLFixed, q[0])

			data["Q"] = q[0]
			data["QueryParts"] = parts

			products, err := runProductQuery(query)
			if err != nil {
				// VULNERABLE: DBのエラーメッセージをそのまま画面に出している。
				data["Error"] = err.Error()
			} else {
				data["Products"] = products
				data["Searched"] = true
			}
		}

		render(w, r, "sqli_search.html", data)
	}
}

// registerSQLiRoutes は SQLインジェクション関連のルートを登録する。
func registerSQLiRoutes(mux *http.ServeMux) {
	mux.Handle("GET /sqli/login", sqliLoginPageHandler())
	mux.Handle("POST /sqli/login", sqliLoginPostHandler())
	mux.Handle("GET /sqli/search", sqliSearchHandler())
}

// runProductQuery は4列(id, name, description, price)を返すクエリを実行する。
// UNION で別テーブルの値を差し込めるよう、全列を文字列として受け取る。
func runProductQuery(query string) ([]Product, error) {
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var id, name, desc, price sql.NullString
		if err := rows.Scan(&id, &name, &desc, &price); err != nil {
			return nil, err
		}
		products = append(products, Product{id.String, name.String, desc.String, price.String})
	}
	return products, rows.Err()
}
