package auth

import (
	"net/http"
    "github.com/wyhisphper/docker_auth/config"
    "golang.org/x/crypto/bcrypt"
)

type account struct {
	username string
	password string
}

func (a *account) Check() error {
    user_password := config.GetUserPassword(a.username);
    if err := bcrypt.CompareHashAndPassword([]byte(user_password), []byte(a.password)); err != nil {
	    return err 
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
