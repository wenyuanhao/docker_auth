package server

import (
	"github.com/wyhisphper/docker_auth/config"
	"log"
	"net/http"
)

type authServer struct {
	listenAddr string
	server     *http.Server
	closeChan  chan bool
}

var as *authServer

func init() {
	as = &authServer{
		closeChan: make(chan bool),
	}
}

func GetServer() *authServer {
	return as
}

func RestartServer() {
	err := config.LoadConfig()
	if err != nil {
		log.Println("can not load config: ", err)
		return
	}
	log.Println("restarting server...")
	as.server.Shutdown(nil)
	<-as.closeChan
	//err = as.server.Close()
	//err = as.StartServer()
	as.setListenAddr()
	as.listenAndServe()
}

func (as *authServer) StartServer() {
	as.setListenAddr()
	as.listenAndServe()
	config.WatchConfig(RestartServer)
}

func (as *authServer) setListenAddr() {
	as.listenAddr = config.GetListenAddr()
}

func (as *authServer) listenAndServe() {
	if len(as.listenAddr) == 0 {
		log.Println("port can't be empty")
		return
	}
	as.server = &http.Server{
		Addr:    as.listenAddr,
		Handler: mux,
	}
	go func() {
		err := as.server.ListenAndServe()
		log.Println(err)
		as.closeChan <- true
	}()
	return
}
