package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/docker/distribution/registry/auth/token"
	"github.com/wyhisphper/docker_auth/config"
	"github.com/wyhisphper/docker_auth/lib"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func getResourceActions(r *http.Request) []*token.ResourceActions {
	account, _, _ := r.BasicAuth()
    acc_actions := config.GetUserAction(account)
    if acc_actions == nil {
        return nil
    }
	r.ParseForm()
	var resActions []*token.ResourceActions
	if r.FormValue("scope") != "" {
		for _, scopeStr := range r.Form["scope"] {
			parts := strings.Split(scopeStr, ":")
			//var resAction token.ResourceActions
			var ty, name string
			var actions []string
			switch len(parts) {
			case 3:
				ty = parts[0]
				name = parts[1]
				actions = strings.Split(parts[2], ",")
			case 4:
				ty = parts[0]
				name = parts[1] + ":" + parts[2]
				actions = strings.Split(parts[2], ",")
			default:
				fmt.Errorf("invalid scope: %q", scopeStr)
			}
			resAction := &token.ResourceActions{
				Type:    ty,
				Name:    name,
				Actions: lib.StringSetIntersection(actions, acc_actions),
			}
			resActions = append(resActions, resAction)
		}
	}
	return resActions
}

func MakeTokenJSON(r *http.Request) []byte {
	pubK, priK, err := config.LoadCertAndKey()
	if err != nil {
		log.Fatal("load cert and key error:", err)
	}
	_, alg, err := priK.Sign(strings.NewReader("ttt"), 0)
	if err != nil {
		log.Fatal("failed to sign: %s", err)
		return []byte("")
	}
	header := token.Header{
		Type:       "JWT",
		SigningAlg: alg,
		KeyID:      pubK.KeyID(),
	}
	headerJSON, err := json.Marshal(header)
	now := time.Now().Unix()
	issuer, expir := config.GetIssuerAndExpire()
	c := token.ClaimSet{
		Issuer:     issuer,
		Subject:    r.Form["account"][0],
		Audience:   r.Form["service"][0],
		NotBefore:  now - 10,
		IssuedAt:   now,
		Expiration: now + expir,
		JWTID:      fmt.Sprintf("%d", rand.Int63()),
		Access:     getResourceActions(r),
	}
	claimJSON, err := json.Marshal(c)
	payload := fmt.Sprintf("%s%s%s", joseBase64UrlEncode(headerJSON), token.TokenSeparator, joseBase64UrlEncode(claimJSON))
	var signatureBytes []byte
	if signatureBytes, _, err = priK.Sign(strings.NewReader(payload), 0); err != nil {
		fmt.Errorf("unable to sign jwt payload: %s", err)
	}
	signature := joseBase64UrlEncode(signatureBytes)
	tokenString := fmt.Sprintf("%s.%s", payload, signature)
	tokenJSON, _ := json.Marshal(map[string]string{"token": tokenString})
	return tokenJSON
}

func joseBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
