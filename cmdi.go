package main

import (
	"context"
	"html/template"
	"net/http"
	"os/exec"
	"time"
)

// このファイルはコマンドインジェクションを体験するための「意図的に脆弱な」実装を含む。
// 入力値をシェルのコマンド文字列に連結している箇所(VULNERABLE)は、学習のためにわざとそうしている。
// 実際にシェルが実行されるため、サーバーは 127.0.0.1 にのみバインドしている。

func cmdiPingHandler(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]any{"Title": "コマンドインジェクション: ping"}

		if h, ok := r.URL.Query()["host"]; ok && len(h) > 0 && h[0] != "" {
			host := h[0]

			// VULNERABLE: 入力値をそのままシェルのコマンド文字列に連結している。
			// ; && | ` $() などのシェルのメタ文字で、任意のコマンドを続けて実行できる。
			// 本来は sh -c を使わず exec.Command("ping", "-c", "1", host) のように引数を分け、
			// host も許可リスト(正規表現)で検証する。
			command := "ping -c 1 -W 2 " + host

			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "sh", "-c", command)
			cmd.WaitDelay = time.Second
			out, err := cmd.CombinedOutput()

			data["Host"] = host
			data["Command"] = command
			data["Output"] = string(out)
			if err != nil {
				data["Err"] = err.Error()
			}
		}

		render(w, tmpl, "cmdi_ping.html", data)
	}
}

// registerCmdiRoutes はコマンドインジェクション関連のルートを登録する。
func registerCmdiRoutes(mux *http.ServeMux) {
	tmpl := parseTemplate("cmdi_ping.html")
	mux.Handle("GET /cmdi/ping", cmdiPingHandler(tmpl))
}
