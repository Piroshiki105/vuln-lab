package main

import (
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"time"
)

// このファイルはメールヘッダインジェクションを体験するための「意図的に脆弱な」実装を含む。
// お問い合わせを受け付けると、入力されたメールアドレス宛に自動返信メールを送る想定。
// SMTP はヘッダを \r\n(CRLF)で区切られた行の並びとして解釈する。
// 入力値(件名・お名前)を検証せずヘッダに連結すると、入力に含まれる \r\n が新しいヘッダ行の
// 区切りとして解釈され、任意のヘッダや本文を注入できてしまう。その結果、攻撃者が指定した
// 別人(被害者)のもとへ、正規の窓口を差出人とした偽のメールが届く。
//
// SMTPサーバーに渡す直前の生のメッセージは画面に表示する。環境変数 SMTP_ADDR が
// 設定されている場合(make 経由で起動した場合の smtp4dev など)は、そのメッセージを実際に送信する。
// 未設定なら送信せず、プレビュー表示のみ行う。
// 安全のため、送信先のSMTPサーバーは smtp4dev / localhost / 127.0.0.1 に限定している。

const (
	// 封筒の差出人(SMTPのMAIL FROM)とメッセージの差出人(From ヘッダ)は固定値。
	// 封筒の宛先(RCPT TO)は入力されたメールアドレスだが、net/smtp が改行を含むアドレスを
	// 拒否するため、脆弱なのはメッセージ本体のヘッダ部分(件名・お名前)に限られる。
	mailEnvelopeFrom = "contact-form@vuln-lab.local"
	mailSupportFrom  = "サポート窓口 <support@example.com>"

	// smtp4dev の受信メール確認画面(compose.yml でホストの 127.0.0.1 に公開している)。
	mailViewerURL = "http://127.0.0.1:5000"
)

// allowedSMTPHosts は SMTP_ADDR に指定できるホスト。実在のSMTPサーバーへ誤って
// 送信しないようにするための制限。
var allowedSMTPHosts = map[string]bool{"smtp4dev": true, "localhost": true, "127.0.0.1": true}

// sendMail は組み立て済みの生メッセージを SMTP_ADDR のサーバーへ送信する。to は封筒の宛先。
func sendMail(addr, to, raw string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("SMTP_ADDR が不正です: %w", err)
	}
	if !allowedSMTPHosts[host] {
		return fmt.Errorf("SMTP_ADDR のホスト %q は許可されていません(smtp4dev / localhost / 127.0.0.1 のみ)", host)
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.Mail(mailEnvelopeFrom); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(raw)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

const mailContactTitle = "メールヘッダインジェクション: お問い合わせ"

// mailContactPageHandler はお問い合わせフォームを表示する。
func mailContactPageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render(w, r, "mail_contact.html", map[string]any{"Title": mailContactTitle})
	}
}

// mailContactPostHandler はお問い合わせを受け付け、自動返信メールを組み立てる。
func mailContactPostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]any{"Title": mailContactTitle}

		name := r.FormValue("name")
		email := r.FormValue("email")
		subject := r.FormValue("subject")
		body := r.FormValue("body")

		// VULNERABLE: 入力値(特に subject と name)を検証せず、そのままメールヘッダに
		// 文字列連結している。本来は \r や \n を含む値を拒否するか、net/mail の
		// Address 型のような、ヘッダを安全に組み立てる仕組みを使う。
		raw := "To: " + name + " <" + email + ">\r\n" +
			"From: " + mailSupportFrom + "\r\n" +
			"Subject: 【受付完了】" + subject + "\r\n" +
			"\r\n" +
			name + " 様\r\n\r\n" +
			"お問い合わせありがとうございます。以下の内容で受け付けました。\r\n" +
			"担当者より後日ご連絡します。\r\n\r\n" +
			"--- お問い合わせ内容 ---\r\n" +
			body

		data["Name"] = name
		data["Email"] = email
		data["Subject"] = subject
		data["Body"] = body
		data["Raw"] = raw
		data["Sent"] = true

		if addr := os.Getenv("SMTP_ADDR"); addr != "" {
			data["MailEnabled"] = true
			data["MailViewerURL"] = mailViewerURL
			if err := sendMail(addr, email, raw); err != nil {
				data["SendError"] = err.Error()
			}
		}

		render(w, r, "mail_contact.html", data)
	}
}

// registerMailRoutes はメールヘッダインジェクション関連のルートを登録する。
func registerMailRoutes(mux *http.ServeMux) {
	mux.Handle("GET /mail/contact", mailContactPageHandler())
	mux.Handle("POST /mail/contact", mailContactPostHandler())
}
