package main

import (
	"html/template"
	"log"
	"net/http"
)

// parseTemplate は共通レイアウト(layout.html)と指定のページをまとめて読み込む。
// 起動時に一度だけ呼ぶ想定で、失敗したらその場で落とす(template.Must)。
func parseTemplate(page string) *template.Template {
	return template.Must(template.ParseFiles("templates/layout.html", "templates/"+page))
}

// render はテンプレートを実行してレスポンスに書き出す。
// Content-Type の設定とエラーログ出力を各ハンドラで繰り返さないための共通処理。
func render(w http.ResponseWriter, tmpl *template.Template, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Println(err)
	}
}
