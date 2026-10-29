package main

import (
	"html/template"
	"net/http"
)

// このファイルはメールヘッダインジェクションを体験するための「意図的に脆弱な」実装を含む。
// SMTP はヘッダを \r\n(CRLF)で区切られた行の並びとして解釈する。
// 入力値を検証せずヘッダに連結すると、入力に含まれる \r\n が新しいヘッダ行の区切りとして
// 解釈され、Bcc の追加や From の偽装など、任意のヘッダを注入できてしまう。
//
// 安全のため、このラボでは実際にメールを送信せず、SMTPサーバーに渡す直前の
// 生のメッセージを画面に表示するだけにしている。

func mailContactHandler(tmpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]any{"Title": "メールヘッダインジェクション: お問い合わせ"}

		if r.Method == http.MethodPost {
			name := r.FormValue("name")
			email := r.FormValue("email")
			subject := r.FormValue("subject")
			body := r.FormValue("body")

			// VULNERABLE: 入力値(特に email と subject)を検証せず、そのままメールヘッダに
			// 文字列連結している。本来は \r や \n を含む値を拒否するか、net/mail の
			// Address 型のような、ヘッダを安全に組み立てる仕組みを使う。
			raw := "To: support@example.com\r\n" +
				"From: " + name + " <" + email + ">\r\n" +
				"Subject: " + subject + "\r\n" +
				"\r\n" +
				body

			data["Name"] = name
			data["Email"] = email
			data["Subject"] = subject
			data["Body"] = body
			data["Raw"] = raw
			data["Sent"] = true
		}

		render(w, tmpl, "mail_contact.html", data)
	}
}

// registerMailRoutes はメールヘッダインジェクション関連のルートを登録する。
func registerMailRoutes(mux *http.ServeMux) {
	tmpl := parseTemplate("mail_contact.html")
	mux.Handle("GET /mail/contact", mailContactHandler(tmpl))
	mux.Handle("POST /mail/contact", mailContactHandler(tmpl))
}
