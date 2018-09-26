package main

import (
	"github.com/wyhisphper/docker_auth/server"
	"log"
)

func main() {
	log.Print("Starting Auth Server")
	as := server.GetServer()
	as.StartServer()
	/*if err != nil {
		log.Fatal("ListenAndServe Fail: ", err)
	}*/
}
