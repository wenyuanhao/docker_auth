package main

import (
	"github.com/wyhisphper/docker_auth/server"
	"log"
)

func main() {
	log.Print("Starting Auth Server")
	as := server.NewServer()
	err := as.ListenAndServe()
	if err != nil {
		log.Fatal("ListenAndServe Fail: ", err)
	}
}
