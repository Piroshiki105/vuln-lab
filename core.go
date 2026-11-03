package main

import (
	"net/http"
)

// このファイルは、特定の脆弱性に属さない共通部分(トップページ、テナント判定)をまとめたもの。

// 認証などが入るまでは固定のテナントIDを使う。
const currentOrgID = 1

func indexHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, "index.html", map[string]any{"Title": "トップ"})
	}
}

// orgIDFromRequest はリクエストからテナントIDを決める
func orgIDFromRequest(_ *http.Request) int {
	return currentOrgID
}

// registerCoreRoutes はトップページのルートを登録する。
func registerCoreRoutes(mux *http.ServeMux) {
	mux.Handle("GET /{$}", indexHandler())
}
