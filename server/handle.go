package server

import (
	"github.com/wyhisphper/docker_auth/auth"
	"net/http"
)

type serverMux struct{}

var mux *serverMux

func (mux *serverMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/auth" {
		handleAuth(w, r)
	} else {
		handleDefault(w, r)
	}
	return
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	account := auth.NewAccount(r)
	err := account.Check()
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	tokenJSON := auth.MakeTokenJSON(r)
	w.Write(tokenJSON)
}

func handleDefault(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("the auth url is /auth"))
}

func init() {
	mux = &serverMux{}
}
