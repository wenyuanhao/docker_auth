package config

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"github.com/docker/libtrust"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
)

type ServerConfig struct {
	Addr     string `yaml:"addr,omitempty"`
	CertFile string `yaml:"cert,omitempty"`
	KeyFile  string `yaml:"key,omitempty"`
}
type TokenConfig struct {
	Issuer     string `yaml:"issuer,omitempty"`
	Expiration int    `yaml:"expiration,omitempty"`
}

type ACLConfig struct {
	Account string   `yaml:"account,omitempty"`
	Image   string   `yaml:"image,omitempty"`
	Actions []string `yaml:"actions,omitempty"`
}
type UserConfig struct {
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

type Config struct {
	Server ServerConfig
	Token  TokenConfig
	Users  []*UserConfig
	ACL    []*ACLConfig
}
type userInfo struct {
	username string
	password string
	image    string
	actions  []string
}

var (
	c       = &Config{}
	cf      string
	userMap map[string]*userInfo
)

func LoadConfig() error {
	data, err := ioutil.ReadFile(cf)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal([]byte(data), c)
	if err != nil {
		return err
	}
	return nil
}

func makeUserMap() {
	userMap = make(map[string]*userInfo, len(c.Users))
	for _, uc := range c.Users {
		userMap[uc.Username] = &userInfo{
			username: uc.Username,
			password: uc.Password,
		}
	}

	for _, ACL := range c.ACL {
		if _, ok := userMap[ACL.Account]; !ok {
			continue
		}
		userMap[ACL.Account].image = ACL.Image
		userMap[ACL.Account].actions = ACL.Actions
	}
}

func init() {
	flag.Parse()
	cf = flag.Arg(0)
	if cf == "" {
		log.Fatal("need config file")
	}
	err := LoadConfig()
	if err != nil {
		log.Fatal("Can not load config", err)
	}
	makeUserMap()
}

func LoadCertAndKey() (pk libtrust.PublicKey, prk libtrust.PrivateKey, err error) {
	cert, err := tls.LoadX509KeyPair(c.Server.CertFile, c.Server.KeyFile)
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

func GetListenAddr() string {
	return c.Server.Addr
}

func GetIssuerAndExpire() (string, int64) {
	return c.Token.Issuer, int64(c.Token.Expiration)
}
