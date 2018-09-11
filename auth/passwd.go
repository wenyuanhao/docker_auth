package auth

import (
	"errors"
	"net/http"
)

type account struct {
	username string
	password string
}

func (a *account) Check() error {
	if a.username != "admin" || a.password != "123456" {
		return errors.New("Auth failed")
	}
	return nil
}

func NewAccount(r *http.Request) *account {
	user, pwd, _ := r.BasicAuth()
	return &account{
		user,
		pwd,
	}
}
