package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/docker/distribution/registry/auth/token"
	"github.com/docker/libtrust"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func getResourceActions(r *http.Request) []*token.ResourceActions {
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
				Actions: actions,
			}
			resActions = append(resActions, resAction)
		}
	}
	return resActions
}

func MakeTokenJSON(r *http.Request) []byte {
	pubK, priK, _ := loadCertAndKey("/path/to/crt", "/peth/to/key")
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
	c := token.ClaimSet{
		Issuer:     "Auth Service",
		Subject:    "admin",
		Audience:   "Docker registry",
		NotBefore:  now - 10,
		IssuedAt:   now,
		Expiration: now + 60,
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

func loadCertAndKey(certFile, keyFile string) (pk libtrust.PublicKey, prk libtrust.PrivateKey, err error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	pk, err = libtrust.FromCryptoPublicKey(x509Cert.PublicKey)
	if err != nil {
		return
	}
	prk, err = libtrust.FromCryptoPrivateKey(cert.PrivateKey)
	return
}

func joseBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
