package main

import (
	"bufio"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"net"
	"os"
	"strings"

	_ "github.com/googleapis/go-sql-spanner"
)

// 接続先は Cloud Spanner エミュレーターに限定する。autoConfigEmulator により、
// インスタンスとデータベースはエミュレーター上に自動で作られる。
// autoConfigEmulator は DSN にホストがないと localhost:9010 を使う(SPANNER_EMULATOR_HOST より優先される)ため、
// 接続時に checkEmulatorHost で検証済みの SPANNER_EMULATOR_HOST を先頭に付ける。
const spannerDSNPath = "projects/vuln-lab/instances/vuln-lab/databases/vuln-lab?autoConfigEmulator=true"

// allowedEmulatorHosts は SPANNER_EMULATOR_HOST に指定できるホスト。実際の Google Cloud に
// 誤って接続しないようにするための制限。
var allowedEmulatorHosts = map[string]bool{"spanner": true, "localhost": true, "127.0.0.1": true}

func checkEmulatorHost() error {
	hostport := os.Getenv("SPANNER_EMULATOR_HOST")
	if hostport == "" {
		return errors.New("SPANNER_EMULATOR_HOST が未設定です(例: 127.0.0.1:9010。devcontainer では自動で設定される)")
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return fmt.Errorf("SPANNER_EMULATOR_HOST が不正です: %w", err)
	}
	if !allowedEmulatorHosts[host] {
		return fmt.Errorf("SPANNER_EMULATOR_HOST のホスト %q は許可されていません(spanner / localhost / 127.0.0.1 のみ)", host)
	}
	return nil
}

//go:embed sql/*.sql
var sqlFS embed.FS

var db *sql.DB

func closeDB() {
	_ = db.Close()
}

// yield を使いたいだけ。巨大なSQLファイルに対して効率的か(？)
func readSQLFile(file fs.File) iter.Seq[string] {
	reader := bufio.NewReader(file)
	return func(yield func(string) bool) {
		for {
			stmt, err := reader.ReadString(';')
			// ReadString は区切りの ";" を含めて返すが、Spanner は末尾の ";" を受け付けないため取り除く。
			stmt = strings.TrimSpace(strings.TrimSuffix(stmt, ";"))
			if stmt != "" {
				if !yield(stmt) {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
}

func execSingleSQLFile(name string) error {
	file, err := sqlFS.Open(name)
	if err != nil {
		return err
	}
	defer file.Close()

	// Spanner は DDL を複数文まとめて実行できないため、";" で区切って 1 文ずつ実行する。
	// SQL ファイル内の文字列やコメントに ";" を含めないこと。
	for stmt := range readSQLFile(file) {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}

	return nil
}

func execSQLFile(names ...string) error {
	for _, name := range names {
		err := execSingleSQLFile(name)
		if err != nil {
			return err
		}
	}
	return nil
}

// seedIfEmpty はテーブルが空のときだけ、シード用の SQL ファイルを実行する。
func seedIfEmpty(table, file string) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	return execSQLFile(file)
}

func initDB() error {
	if err := checkEmulatorHost(); err != nil {
		return err
	}

	var err error
	db, err = sql.Open("spanner", os.Getenv("SPANNER_EMULATOR_HOST")+"/"+spannerDSNPath)
	if err != nil {
		return err
	}

	if err := execSQLFile("sql/01.create-table.sql"); err != nil {
		return err
	}

	seeds := []struct{ table, file string }{
		{"organizations", "sql/02.organization-seed.sql"},
		{"accounts", "sql/03.account-seed.sql"},
		{"products", "sql/04.product-seed.sql"},
	}
	for _, s := range seeds {
		if err := seedIfEmpty(s.table, s.file); err != nil {
			return err
		}
	}

	if err := initCSRFBalances(); err != nil {
		return err
	}
	return initComments()
}

func initCSRFBalances() error {
	return seedIfEmpty("csrf_balances", "sql/05.csrf-balance-seed.sql")
}

func initComments() error {
	return seedIfEmpty("comments", "sql/06.comment-seed.sql")
}
