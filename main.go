package main

import (
	//"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/docker/libtrust"
	//"github.com/docker/distribution/vendor/github.com/docker/libtrust"
	"github.com/docker/distribution/registry/auth/token"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
	//"reflect"
)
type authScope struct {
    Type    string
    Name    string
    Actions []string
}

func HandleAuth(w http.ResponseWriter, r *http.Request) {
	//fmt.Println(r.Header)
	r.ParseForm()
	//fmt.Println(r.Form)
	log.Print(r.Form)
    if r.Form["account"] == nil {
        http.Error(w, "Auth failed.", http.StatusUnauthorized)
        return
    }
    var s []authScope
    if r.FormValue("scope") != "" {
        for _, scopeStr := range r.Form["scope"] {
            parts := strings.Split(scopeStr, ":")
            var scope authScope
            switch len(parts) {
            case 3:
                scope = authScope{
                    Type:    parts[0],
                    Name:    parts[1],
                    Actions: strings.Split(parts[2], ","),
                }
            case 4:
                scope = authScope{
                    Type:    parts[0],
                    Name:    parts[1] + ":" + parts[2],
                    Actions: strings.Split(parts[3], ","),
                }
            default:
                fmt.Errorf("invalid scope: %q", scopeStr)
            }
            s = append(s, scope)
        }
    }
	log.Print(s)
	res := createToken(s)
	fmt.Println(string(res))
	w.Write(res)
	//fmt.Fprintf(w, createToken())
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

func getRsaKey() {
	pubK, priK, _ := loadCertAndKey("/home/wenyuanhao/auth_server/ssl/server.crt", "/home/wenyuanhao/auth_server/ssl/server.key")
	fmt.Println(pubK, priK)
}

func main() {
	log.Print("ListenAndServe Starting")
	http.HandleFunc("/auth", HandleAuth)
	err := http.ListenAndServe(":6767", nil)
	if err != nil {
		log.Fatal("ListenAndServe Fail: " + err.Error())
	}
}
func joseBase64UrlEncode(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

func createToken(s []authScope) []byte {
	pubK, priK, _ := loadCertAndKey("/home/wenyuanhao/auth_server/ssl/server.crt", "/home/wenyuanhao/auth_server/ssl/server.key")
	_, alg, _ := priK.Sign(strings.NewReader("ttt"), 0)
	/*rootKeys, err := makeRootKeys(1)
	signingKey, err := makeSigningKeyWithChain(rootKeys[0], 0)
	var rawJWK json.RawMessage
	rawJWK, err = signingKey.PublicKey().MarshalJSON()*/
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
		Access: []*token.ResourceActions{},
		//Access:     []*token.ResourceActions{},
	}
    for _, scope := range s {
        ra := &token.ResourceActions{
            Type:    scope.Type,
            Name:    scope.Name,
            Actions: scope.Actions,
        }
        c.Access = append(c.Access, ra)
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

	/*
	   t, _ := token.NewToken(tokenString+"a")
	   tokenJSON, _ := json.Marshal(map[string]string{"token" : tokenString})
	   rootCerts, err := makeRootCerts(rootKeys)
	   trustedKeys := makeTrustedKeyMap(rootKeys)
	   rootPool := x509.NewCertPool()
	   for _, rootCert := range rootCerts {
	       rootPool.AddCert(rootCert)
	   }
	   //fmt.Println(reflect.TypeOf(rootPool))
	   verifyOps := token.VerifyOptions{
	       TrustedIssuers:    []string{"Auth Service"},
	       AcceptedAudiences: []string{"Docker registry"},
	       Roots:             rootPool,
	       TrustedKeys:       trustedKeys,
	   }
	   t.Verify(verifyOps)
	   return []byte(tokenString)*/
}

func makeRootKeys(numKeys int) ([]libtrust.PrivateKey, error) {
	keys := make([]libtrust.PrivateKey, 0, numKeys)
	for i := 0; i < numKeys; i++ {
		key, err := libtrust.GenerateECP256PrivateKey()
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return keys, nil
}

func makeSigningKeyWithChain(rootKey libtrust.PrivateKey, depth int) (libtrust.PrivateKey, error) {
	if depth == 0 {
		// Don't need to build a chain.
		return rootKey, nil
	}

	var (
		x5c       = make([]string, depth)
		parentKey = rootKey
		key       libtrust.PrivateKey
		cert      *x509.Certificate
		err       error
	)

	for depth > 0 {
		if key, err = libtrust.GenerateECP256PrivateKey(); err != nil {
			return nil, err
		}

		if cert, err = libtrust.GenerateCACert(parentKey, key); err != nil {
			return nil, err
		}

		depth--
		x5c[depth] = base64.StdEncoding.EncodeToString(cert.Raw)
		parentKey = key
	}

	key.AddExtendedField("x5c", x5c)

	return key, nil
}

func makeRootCerts(rootKeys []libtrust.PrivateKey) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(rootKeys))

	for _, key := range rootKeys {
		cert, err := libtrust.GenerateCACert(key, key)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

func makeTrustedKeyMap(rootKeys []libtrust.PrivateKey) map[string]libtrust.PublicKey {
	trustedKeys := make(map[string]libtrust.PublicKey, len(rootKeys))

	for _, key := range rootKeys {
		trustedKeys[key.KeyID()] = key.PublicKey()
	}
	return trustedKeys
}
