package main

import (
	"log"
	"net/http"
)

// listenAddr は必ず localhost に限定する。意図的に脆弱なアプリを外部に公開しないため。
const listenAddr = "127.0.0.1:8080"

func main() {
	if err := initDB(); err != nil {
		log.Fatal(err)
	}
	defer closeDB()

	if err := initTemplates(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	registerCoreRoutes(mux)
	registerSQLiRoutes(mux)
	registerXSSRoutes(mux)
	registerCSRFRoutes(mux)
	registerCmdiRoutes(mux)
	registerPathtravRoutes(mux)
	registerMailRoutes(mux)
	registerHeaderRoutes(mux)

	log.Println("WARNING: vuln-lab は意図的に脆弱なアプリです。ローカル学習専用です。公開しないでください。")
	log.Printf("listening on http://%s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
