package main

import (
	"database/sql"
	"html/template"
	"net/http"
)

// このファイルは、特定の脆弱性に属さない共通部分(トップページ、組織・ユーザー一覧、
// テナント判定)をまとめたもの。/users は後の段階(マルチテナントのパストラバーサル等)の
// 題材として残している。

// 認証などが入るまでは固定のテナントIDを使う。
const currentOrgID = 1

type User struct {
	ID        int
	Name      string
	Email     string
	CreatedAt string
}

func indexHandler(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, tmpl, "index.html", map[string]any{"Title": "トップ"})
	}
}

// orgIDFromRequest はリクエストからテナントIDを決める。後で認証等に差し替える。
func orgIDFromRequest(r *http.Request) int {
	return currentOrgID
}

func hasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func initDB(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS organizations (
		id   INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL
	)`); err != nil {
		return err
	}

	var orgCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM organizations`).Scan(&orgCount); err != nil {
		return err
	}
	seededOrgs := orgCount == 0
	if seededOrgs {
		if _, err := db.Exec(`INSERT INTO organizations (name) VALUES ('株式会社アルファ'), ('ベータ合同会社')`); err != nil {
			return err
		}
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		organization_id INTEGER NOT NULL REFERENCES organizations(id),
		name            TEXT NOT NULL,
		email           TEXT NOT NULL UNIQUE,
		created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return err
	}

	// 既存DB(organization_id なし)のマイグレーション。
	// SQLite は NOT NULL かつ REFERENCES の列を ALTER で追加できないため、
	// 既存ユーザーは組織1に所属させ、外部キー制約は付けない。
	ok, err := hasColumn(db, "users", "organization_id")
	if err != nil {
		return err
	}
	if !ok {
		if _, err := db.Exec(`ALTER TABLE users ADD COLUMN organization_id INTEGER NOT NULL DEFAULT 1`); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users(organization_id)`); err != nil {
		return err
	}

	var userCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&userCount); err != nil {
		return err
	}
	if userCount == 0 {
		if _, err := db.Exec(`INSERT INTO users (organization_id, name, email) VALUES
			(1, '山田 太郎', 'taro@example.com'),
			(1, '佐藤 花子', 'hanako@example.com'),
			(1, '鈴木 一郎', 'ichiro@example.com')`); err != nil {
			return err
		}
	}
	if seededOrgs {
		if _, err := db.Exec(`INSERT INTO users (organization_id, name, email) VALUES
			(2, '高橋 次郎', 'jiro@example.org'),
			(2, '伊藤 美咲', 'misaki@example.org')`); err != nil {
			return err
		}
	}
	return nil
}

func usersHandler(db *sql.DB, tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := orgIDFromRequest(r)

		var orgName string
		err := db.QueryRow(`SELECT name FROM organizations WHERE id = ?`, orgID).Scan(&orgName)
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		rows, err := db.Query(
			`SELECT id, name, email, created_at FROM users WHERE organization_id = ? ORDER BY id`,
			orgID,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var users []User
		for rows.Next() {
			var u User
			if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.CreatedAt); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			users = append(users, u)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := map[string]any{"Title": orgName + " のユーザー一覧", "OrgName": orgName, "Users": users}
		render(w, tmpl, "users.html", data)
	}
}

// registerCoreRoutes は共通スキーマの初期化と、トップページ・ユーザー一覧のルートを登録する。
func registerCoreRoutes(mux *http.ServeMux, db *sql.DB) error {
	if err := initDB(db); err != nil {
		return err
	}
	indexTmpl := parseTemplate("index.html")
	usersTmpl := parseTemplate("users.html")
	mux.Handle("GET /{$}", indexHandler(indexTmpl))
	mux.Handle("GET /users", usersHandler(db, usersTmpl))
	return nil
}
