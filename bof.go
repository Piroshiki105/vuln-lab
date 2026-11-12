package main

import "net/http"

// このファイルはバッファオーバーフロー(IPA 1.10)の解説ページ。
// Go はメモリ安全な言語のため、脆弱な実装は用意せず、静的な解説だけを返す。

func bofHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, r, "bof.html", map[string]any{"Title": "バッファオーバーフロー(解説)"})
	}
}

// registerBofRoutes はバッファオーバーフローの解説ページを登録する。
func registerBofRoutes(mux *http.ServeMux) {
	mux.Handle("GET /bof", bofHandler())
}
