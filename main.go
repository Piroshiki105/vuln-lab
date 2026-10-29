package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "modernc.org/sqlite"
)

// listenAddr は必ず localhost に限定する。意図的に脆弱なアプリを外部に公開しないため。
const listenAddr = "127.0.0.1:8080"

func main() {
	db, err := sql.Open("sqlite", "file:app.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	if err := registerCoreRoutes(mux, db); err != nil {
		log.Fatal(err)
	}
	if err := registerSQLiRoutes(mux, db); err != nil {
		log.Fatal(err)
	}
	if err := registerXSSRoutes(mux, db); err != nil {
		log.Fatal(err)
	}
	if err := registerCSRFRoutes(mux, db); err != nil {
		log.Fatal(err)
	}
	registerCmdiRoutes(mux)
	registerPathtravRoutes(mux, db)
	registerMailRoutes(mux)
	registerHeaderRoutes(mux)

	startTrapServer()

	log.Println("WARNING: vuln-lab は意図的に脆弱なアプリです。ローカル学習専用です。公開しないでください。")
	log.Printf("listening on http://%s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
