package main

import (
	"net/http"
	"strconv"
	"sync"
)

// このファイルはセッション管理の不備(IPA 1.4)を体験するための「意図的に脆弱な」実装を含む。
// CSRF 画面などのセッション(csrf_session)とは別に、専用の Cookie「sid」と専用のストアを持つ。
//   - セッションIDが連番で推測できる(セッションIDの推測)
//   - URL の ?sid= で渡されたIDをそのまま採用し、ログイン時にも発行し直さない(セッションIDの固定化)
//   - Cookie に HttpOnly / Secure を付けていない(JavaScript から読め、盗用されやすい)

const sessionCookieName = "sid"

var sessionLoginConfig = loginConfig{
	Title:  "セッション管理の不備: ログイン",
	Intro:  "セッションIDの扱いを体験するため、まずログインします。SQLインジェクションの画面と同じアカウントを使えます(例: alice / password1)。この画面を開いた時点で、ログイン前でもセッションID(Cookie「sid」)が発行されます。",
	Action: "/session/login",
	Next:   "/session/home",
	IPA:    "1.4",
	CWE:    "CWE-330 / CWE-384 / CWE-614",
}

// ログイン前後のセッション(ID -> ユーザー名)。ログイン前は空文字。
var (
	sessionMu   sync.Mutex
	sessionNext = 1000
	sessions    = map[string]string{}
	// ログインしたときに、ブラウザが持っていたID(ログイン前のID)。キーはログイン後のID。画面の解説用。
	sessionBeforeLogin = map[string]string{}
)

// sessionNewID は新しいIDを発行して空のセッションを作る。呼び出し側がロックを持っていること。
func sessionNewID() string {
	// VULNERABLE: 連番のIDを発行している。1 つ受け取れば他の人のIDが推測できる。
	// 本来は暗号論的乱数(crypto/rand)で十分な長さの値を生成する。
	sessionNext++
	id := strconv.Itoa(sessionNext)
	sessions[id] = ""
	return id
}

func sessionCookie(id string) *http.Cookie {
	// VULNERABLE: HttpOnly を付けていないので JavaScript(document.cookie)から読める。
	// Secure も付けていないので、平文の HTTP でも送信される。SameSite も指定していない。
	return &http.Cookie{
		Name:  sessionCookieName,
		Value: id,
		Path:  "/",
	}
}

func sessionSetCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, sessionCookie(id))
}

func sessionCurrentID(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if _, ok := sessions[c.Value]; !ok {
		return ""
	}
	return c.Value
}

func sessionLoginPageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionMu.Lock()
		id := ""
		if v := r.URL.Query().Get("sid"); v != "" {
			// VULNERABLE: URL で渡されたセッションIDをそのまま採用する(セッションIDの固定化)。
			// サーバーが発行していないIDは受け付けないのが本来の姿。
			id = v
			if _, ok := sessions[id]; !ok {
				sessions[id] = ""
			}
		} else if c, err := r.Cookie(sessionCookieName); err == nil {
			if _, ok := sessions[c.Value]; ok {
				id = c.Value
			}
		}
		if id == "" {
			id = sessionNewID()
		}
		user := sessions[id]
		sessionMu.Unlock()

		sessionSetCookie(w, id)
		if user != "" {
			http.Redirect(w, r, sessionLoginConfig.Next, http.StatusSeeOther)
			return
		}
		render(w, r, "login.html", sessionLoginConfig.data(false))
	}
}

func sessionLoginPostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var n int
		err := db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE username = ? AND password = ?`,
			username, password).Scan(&n)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if n == 0 {
			render(w, r, "login.html", sessionLoginConfig.data(true))
			return
		}

		// VULNERABLE: ログイン前から持っているセッションIDをそのまま使い続ける。
		// ログイン成功時に新しいIDへ発行し直せば、事前に仕込まれたIDは無効になる。
		id := sessionCurrentID(r)
		before := id
		sessionMu.Lock()
		if id == "" {
			id = sessionNewID()
		}
		sessionBeforeLogin[id] = before
		sessions[id] = username
		sessionMu.Unlock()

		sessionSetCookie(w, id)
		http.Redirect(w, r, sessionLoginConfig.Next, http.StatusSeeOther)
	}
}

func sessionHomeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := sessionCurrentID(r)
		sessionMu.Lock()
		user := sessions[id]
		before, hasBefore := sessionBeforeLogin[id]
		sessionMu.Unlock()
		if user == "" {
			http.Redirect(w, r, "/session/login", http.StatusSeeOther)
			return
		}
		render(w, r, "session_home.html", map[string]any{
			"Title": "セッション管理の不備: マイページ",
			"User":  user,
			"SID":   id,
			// 画面の「内部で何が起きたか」用。
			"SetCookie": sessionCookie(id).String(),
			"HasBefore": hasBefore,
			"BeforeID":  before,
			"SameAsPre": hasBefore && before == id,
		})
	}
}

func sessionLogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if id := sessionCurrentID(r); id != "" {
			sessionMu.Lock()
			delete(sessions, id)
			sessionMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/session/login", http.StatusSeeOther)
	}
}

// registerSessionRoutes はセッション管理の不備に関するルートを登録する。
func registerSessionRoutes(mux *http.ServeMux) {
	mux.Handle("GET /session/login", sessionLoginPageHandler())
	mux.Handle("POST /session/login", sessionLoginPostHandler())
	mux.Handle("GET /session/home", sessionHomeHandler())
	mux.Handle("POST /session/logout", sessionLogoutHandler())
}
