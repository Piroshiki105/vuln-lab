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

// render はテンプレートを実行してレスポンスに書き出す。
// Content-Type の設定とエラーログ出力を各ハンドラで繰り返さないための共通処理。
func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := templates.Lookup(name)
	if tmpl == nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Println(err)
	}
}
