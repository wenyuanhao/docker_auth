package server

import (
	"github.com/wyhisphper/docker_auth/auth"
	"net/http"
	"sync"
)

type serverMux struct {
	wg sync.WaitGroup
}

var mux *serverMux

func (mux *serverMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux.wg.Add(1)
	defer mux.wg.Done()
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
