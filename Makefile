# vuln-lab: 意図的に脆弱な学習用アプリ(ローカル専用)。本体(8080)と罠サーバー(9090)の起動を簡単にする。
# 本体は Cloud Spanner エミュレーターに接続する。SPANNER_EMULATOR_HOST が未設定なら 127.0.0.1:9010 を使う。
# 許可されないホストは、本体側(checkEmulatorHost)が起動時に拒否する。

# up で `jobs` を使うため bash を指定する(既定の sh では使えない)。
SHELL := /bin/bash
COMPOSE := docker compose
export SPANNER_EMULATOR_HOST ?= 127.0.0.1:9010
# メール画面は smtp4dev(compose.yml でホストの 127.0.0.1:2525 に公開)へ実際に送信する。
# 許可されないホストは、本体側が拒否する。プレビューのみにしたい場合は SMTP_ADDR= (空)で起動する。
export SMTP_ADDR ?= 127.0.0.1:2525

.PHONY: up run trap emulator emulator-down vet

# 本体と罠サーバーを同時に起動する。どちらかが終了したら、もう一方も止める(Ctrl-C で両方止まる)。
# go run は SIGTERM を子プロセス(実際のサーバー)へ転送しないため、set -m でジョブごとに
# プロセスグループを分け、終了時にグループ単位(kill -- -PGID)で止める。
# macOS 標準の Bash 3.2 には wait -n がないため、実行中ジョブ数を監視する。
up:
	@set -m; \
	trap 'for p in $$(jobs -pr); do kill -- -$$p 2>/dev/null; done' INT TERM EXIT; \
	(cd trap && go run .) & \
	trap_pid=$$!; \
	go run . & \
	app_pid=$$!; \
	while [ "$$(jobs -pr | wc -l)" -eq 2 ]; do sleep 0.1; done; \
	if jobs -pr | grep -qx "$$app_pid"; then wait "$$trap_pid"; else wait "$$app_pid"; fi

# 本体のみ起動する。
run:
	go run .

# 罠サーバーのみ起動する。
trap:
	cd trap && go run .

# Spanner エミュレーターと smtp4dev を起動する / 停止する(Docker が必要)。
emulator:
	$(COMPOSE) up -d spanner smtp4dev

emulator-down:
	$(COMPOSE) down

# 本体と罠サーバーの両方で go vet を実行する。
vet:
	go vet ./...
	cd trap && go vet ./...
