package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
)

//go:embed templates/*.html
var templatesFS embed.FS

var templates *template.Template

func initTemplates() error {
	var err error
	templates, err = template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return err
	}
	return nil
}

// pageMeta は画面に表示する IPA「安全なウェブサイトの作り方」の項番と、対応する CWE。
type pageMeta struct{ IPA, CWE string }

// templateMeta はテンプレート名ごとの pageMeta。login.html は複数の画面で共有しているため、
// ここには置かず loginConfig 側で持つ。
var templateMeta = map[string]pageMeta{
	"sqli_login.html":         {"1.1", "CWE-89"},
	"sqli_search.html":        {"1.1", "CWE-89"},
	"cmdi_ping.html":          {"1.2", "CWE-78"},
	"pathtrav_view.html":      {"1.3", "CWE-22"},
	"session_home.html":       {"1.4", "CWE-330 / CWE-384 / CWE-614"},
	"xss_reflected.html":      {"1.5", "CWE-79"},
	"xss_board.html":          {"1.5", "CWE-79"},
	"csrf_account.html":       {"1.6", "CWE-352"},
	"header_redirect.html":    {"1.7", "CWE-113"},
	"mail_contact.html":       {"1.8", "CWE-93"},
	"clickjack_settings.html": {"1.9", ""},
	"bof.html":                {"1.10", "CWE-119"},
	"authz_login.html":        {"1.11", ""},
	"authz_profile.html":      {"1.11", ""},
	"authz_admin.html":        {"1.11", ""},
}

// withPageContext は、ヘッダに出す共通の情報(IPA 項番・CWE、ログイン中のユーザー)をデータへ足す。
// 各ハンドラが個別に渡さなくて済むようにするためのもの。元のマップは書き換えない。
func withPageContext(r *http.Request, name string, data any) any {
	m, ok := data.(map[string]any)
	if !ok {
		return data
	}
	out := make(map[string]any, len(m)+4)
	for k, v := range m {
		out[k] = v
	}
	if meta, ok := templateMeta[name]; ok {
		if _, set := out["IPA"]; !set {
			out["IPA"] = meta.IPA
			out["CWE"] = meta.CWE
		}
	}
	// 共通ログイン(csrf_session)と、セッション管理の画面(sid)は別の Cookie で管理している。
	out["SharedUser"] = csrfCurrentUser(r)
	if id := sessionCurrentID(r); id != "" {
		sessionMu.Lock()
		out["SessionUser"] = sessions[id]
		sessionMu.Unlock()
	}
	return out
}

// render はテンプレートを実行してレスポンスに書き出す。
// Content-Type の設定とエラーログ出力を各ハンドラで繰り返さないための共通処理。
func render(w http.ResponseWriter, r *http.Request, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := templates.Lookup(name)
	if tmpl == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if err := tmpl.ExecuteTemplate(w, name, withPageContext(r, name, data)); err != nil {
		log.Println(err)
	}
}
