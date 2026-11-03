# vuln-lab: 意図的に脆弱な学習用アプリ(ローカル専用)。本体(8080)と罠サーバー(9090)の起動を簡単にする。
# 本体は Cloud Spanner エミュレーターに接続する。SPANNER_EMULATOR_HOST が未設定なら 127.0.0.1:9010 を使う。
# 許可されないホストは、本体側(checkEmulatorHost)が起動時に拒否する。

# up で `wait -n` と `jobs` を使うため bash を指定する(既定の sh では使えない)。
SHELL := /bin/bash
COMPOSE := docker compose -f .devcontainer/docker-compose.yml
export SPANNER_EMULATOR_HOST ?= 127.0.0.1:9010

.PHONY: up run trap emulator emulator-down vet

# 本体と罠サーバーを同時に起動する。どちらかが終了したら、もう一方も止める(Ctrl-C で両方止まる)。
# go run は SIGTERM を子プロセス(実際のサーバー)へ転送しないため、set -m でジョブごとに
# プロセスグループを分け、終了時にグループ単位(kill -- -PGID)で止める。
up:
	@set -m; \
	trap 'for p in $$(jobs -p); do kill -- -$$p 2>/dev/null; done' INT TERM EXIT; \
	(cd trap && go run .) & \
	go run . & \
	wait -n

# 本体のみ起動する。
run:
	go run .

# 罠サーバーのみ起動する。
trap:
	cd trap && go run .

# Spanner エミュレーターを起動する / 停止する(Docker が必要)。
emulator:
	$(COMPOSE) up -d spanner

emulator-down:
	$(COMPOSE) stop spanner

# 本体と罠サーバーの両方で go vet を実行する。
vet:
	go vet ./...
	cd trap && go vet ./...
