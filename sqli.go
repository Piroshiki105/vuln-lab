package main

import (
	"database/sql"
	"html/template"
	"net/http"
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

func initSQLiDB(db *sql.DB) error {
	// VULNERABLE: パスワードを平文で保存している(ハッシュ化していない)。
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS accounts (
		id       INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		role     TEXT NOT NULL
	)`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS products (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT NOT NULL,
		description TEXT NOT NULL,
		price       INTEGER NOT NULL,
		is_public   INTEGER NOT NULL DEFAULT 1
	)`); err != nil {
		return err
	}

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := db.Exec(`INSERT INTO accounts (username, password, role) VALUES
			('admin', 'S3cr3t-Adm1n!', 'admin'),
			('alice', 'password1', 'user'),
			('bob', 'qwerty', 'user')`); err != nil {
			return err
		}
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM products`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := db.Exec(`INSERT INTO products (name, description, price, is_public) VALUES
			('ノートPC', '軽量13インチ', 120000, 1),
			('ワイヤレスマウス', '静音タイプ', 3000, 1),
			('メカニカルキーボード', '青軸', 12000, 1),
			('USBメモリ 64GB', '高速転送', 1500, 1),
			('ウェブカメラ', 'フルHD', 5000, 1),
			('【社外秘】新製品プロトタイプ', '発売前のため非公開', 999999, 0),
			('【社外秘】社内向け特別価格モデル', '関係者のみ', 1, 0)`); err != nil {
			return err
		}
	}
	return nil
}

func sqliLoginHandler(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]any{"Title": "SQLインジェクション: ログイン"}

		if r.Method == http.MethodPost {
			username := r.FormValue("username")
			password := r.FormValue("password")

			// VULNERABLE: 入力値をそのままSQL文に連結している。
			// 本来は db.QueryRow("... WHERE username = ? AND password = ?", username, password) のように
			// プレースホルダ(バインド変数)を使う。
			query := "SELECT id, username, role FROM accounts WHERE username = '" + username +
				"' AND password = '" + password + "'"

			data["Username"] = username
			data["Query"] = query

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
		}

		render(w, tmpl, "sqli_login.html", data)
	}
}

func sqliSearchHandler(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]any{"Title": "SQLインジェクション: 商品検索"}

		if q, ok := r.URL.Query()["q"]; ok && len(q) > 0 {
			// VULNERABLE: 検索語をそのままSQL文に連結している。
			// is_public = 1 で非公開商品を隠しているつもりでも、入力次第で条件を崩せる。
			query := "SELECT id, name, description, price FROM products WHERE is_public = 1 AND name LIKE '%" +
				q[0] + "%'"

			data["Q"] = q[0]
			data["Query"] = query

			products, err := runProductQuery(db, query)
			if err != nil {
				// VULNERABLE: DBのエラーメッセージをそのまま画面に出している。
				data["Error"] = err.Error()
			} else {
				data["Products"] = products
				data["Searched"] = true
			}
		}

		render(w, tmpl, "sqli_search.html", data)
	}
}

// registerSQLiRoutes は SQLインジェクション関連のルートを登録する。
func registerSQLiRoutes(mux *http.ServeMux, db *sql.DB) error {
	if err := initSQLiDB(db); err != nil {
		return err
	}
	loginTmpl := parseTemplate("sqli_login.html")
	searchTmpl := parseTemplate("sqli_search.html")
	mux.Handle("GET /sqli/login", sqliLoginHandler(db, loginTmpl))
	mux.Handle("POST /sqli/login", sqliLoginHandler(db, loginTmpl))
	mux.Handle("GET /sqli/search", sqliSearchHandler(db, searchTmpl))
	return nil
}

// runProductQuery は4列(id, name, description, price)を返すクエリを実行する。
// UNION で別テーブルの値を差し込めるよう、全列を文字列として受け取る。
func runProductQuery(db *sql.DB, query string) ([]Product, error) {
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
