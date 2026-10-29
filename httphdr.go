package main

import (
	"html/template"
	"log"
	"net/http"
)

// このファイルは HTTPヘッダインジェクション(レスポンス分割)を体験するための
// 「意図的に脆弱な」実装を含む。
//
// Go の net/http は、ヘッダの値に \r や \n が含まれていると書き込み時に検証し、
// 不正な値を黙って書き込まない(過去のCVEへの対策として標準で組み込まれている)。
// そのため w.Header().Set や http.Redirect をそのまま使う限り、この脆弱性は
// 再現できない。
//
// ここでは http.Hijacker でTCP接続を乗っ取り(VULNERABLE)、レスポンスを
// 生のバイト列として自分で組み立てることで、その保護を意図的にバイパスしている。
// 本来のGoコードでは、ここまでしないとこの脆弱性は作れない、という点も学びになる。

func headerRedirectHandler(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			data := map[string]any{"Title": "HTTPヘッダインジェクション: リダイレクト"}
			render(w, tmpl, "header_redirect.html", data)
			return
		}

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "この接続はHijackできません", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()

		// VULNERABLE: next をそのままヘッダ値として連結している。
		// next に \r\n を含めると新しいヘッダ行(Set-Cookie 等)を追加でき、
		// \r\n\r\n を含めるとヘッダを終端する空行ごと注入して、続く任意の
		// 内容をレスポンスボディとして差し込める(レスポンス分割)。
		raw := "HTTP/1.1 302 Found\r\n" +
			"Location: " + next + "\r\n" +
			"Connection: close\r\n" +
			"\r\n"

		if _, err := bufrw.WriteString(raw); err != nil {
			log.Println(err)
			return
		}
		if err := bufrw.Flush(); err != nil {
			log.Println(err)
		}
	}
}

// registerHeaderRoutes は HTTPヘッダインジェクション関連のルートを登録する。
func registerHeaderRoutes(mux *http.ServeMux) {
	tmpl := parseTemplate("header_redirect.html")
	mux.Handle("GET /header/redirect", headerRedirectHandler(tmpl))
}
