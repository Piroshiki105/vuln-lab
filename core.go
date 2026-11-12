package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
)

// このファイルは、特定の脆弱性に属さない共通部分(トップページ、テナント判定)をまとめたもの。

// 認証などが入るまでは固定のテナントIDを使う。
const currentOrgID = 1

func indexHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, r, "index.html", map[string]any{"Title": "トップ", "Msg": r.URL.Query().Get("msg")})
	}
}

// resetAllHandler は各画面の「初期状態に戻す」処理をまとめて呼ぶ(学習環境の復旧用)。
// 新しい処理は作らず、既存のリセットハンドラの結果だけを確認して、トップページへ戻る。
func resetAllHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resets := []struct {
			name string
			h    http.HandlerFunc
		}{
			{"CSRF(残高・パスワード)", csrfResetHandler()},
			{"XSS 掲示板", xssBoardResetHandler()},
			{"クリックジャッキング(公開状態)", clickjackResetHandler()},
			{"認可(権限)", authzResetHandler()},
		}
		for _, x := range resets {
			rec := httptest.NewRecorder()
			x.h(rec, r)
			if rec.Code >= 400 {
				http.Error(w, fmt.Sprintf("%s のリセットに失敗しました: %s", x.name, rec.Body.String()), http.StatusInternalServerError)
				return
			}
		}
		http.Redirect(w, r, "/?msg=全データを初期状態に戻しました", http.StatusSeeOther)
	}
}

// orgIDFromRequest はリクエストからテナントIDを決める
func orgIDFromRequest(_ *http.Request) int {
	return currentOrgID
}

// registerCoreRoutes はトップページのルートを登録する。
func registerCoreRoutes(mux *http.ServeMux) {
	mux.Handle("GET /{$}", indexHandler())
	mux.Handle("POST /reset-all", resetAllHandler())
}
