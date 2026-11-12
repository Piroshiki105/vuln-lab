package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// このファイルはパストラバーサルを体験するための「意図的に脆弱な」実装を含む。
// マルチテナントを模しており、組織ごとに docs/org<ID>/ を割り当てている。
// 「自組織のディレクトリ配下しか見えない」つもりが、入力値の検証をしていない(VULNERABLE)ため、
// ../ で他組織のディレクトリや docs/ の外にも出られてしまう。

const docsDir = "docs"

func pathtravViewHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := orgIDFromRequest(r)
		var orgName string
		if err := db.QueryRow(`SELECT name FROM organizations WHERE id = ?`, orgID).Scan(&orgName); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// VULNERABLE の一部: 組織ごとのディレクトリ名を ID から機械的に作っている(org1, org2, ...)。
		// 攻撃者は他組織の ID やディレクトリ名を推測しやすい。
		orgDir := filepath.Join(docsDir, fmt.Sprintf("org%d", orgID))

		data := map[string]any{
			"Title":   "パストラバーサル: ファイル閲覧",
			"OrgID":   orgID,
			"OrgName": orgName,
			"OrgDir":  orgDir,
		}

		if f, ok := r.URL.Query()["file"]; ok && len(f) > 0 && f[0] != "" {
			file := f[0]

			// VULNERABLE: ../ を含む入力を検証せずパスに連結している。
			// 自組織のディレクトリ(orgDir)の外、他組織のディレクトリや docs/ の外にあるファイルも読めてしまう。
			// 本来は filepath.Clean 後にベースディレクトリ配下か確認する、または os.Root を使う。
			path := filepath.Join(orgDir, file)

			data["File"] = file
			data["Path"] = path
			// 画面の「内部で何が起きたか」用。実際に読む場所と、自組織のディレクトリの外に出たかを示す。
			absPath, _ := filepath.Abs(path)
			absOrg, _ := filepath.Abs(orgDir)
			data["AbsPath"] = absPath
			data["Escaped"] = !strings.HasPrefix(absPath+string(filepath.Separator), absOrg+string(filepath.Separator))

			content, err := os.ReadFile(path)
			if err != nil {
				// VULNERABLE: OSのエラーメッセージ(パス情報を含む)をそのまま画面に出している。
				data["Error"] = err.Error()
			} else {
				data["Content"] = string(content)
			}
		}

		render(w, r, "pathtrav_view.html", data)
	}
}

// registerPathtravRoutes はパストラバーサル関連のルートを登録する。
func registerPathtravRoutes(mux *http.ServeMux) {
	mux.Handle("GET /path/view", pathtravViewHandler())
}
