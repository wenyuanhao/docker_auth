package server

import (
	"errors"
	"net/http"
)

type authServer struct {
	ipAddr string
	port   string
}

func NewServer() *authServer {
	return &authServer{"", "6767"}
}

func (as *authServer) ListenAndServe() error {
	if len(as.port) == 0 {
		return errors.New("port can't be empty")
	}
	err := http.ListenAndServe(as.ipAddr+":"+as.port, mux)
	return err
}
