package keystone

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/grafana/grafana/pkg/log"
	"github.com/grafana/grafana/pkg/setting"

	"io/ioutil"
)

// From https://golang.org/pkg/net/http:
// "Clients and Transports are safe for concurrent use by multiple goroutines and for efficiency should only be created once and re-used."
var client *http.Client

func GetHttpClient() *http.Client {
	if client != nil {
		return client
	} else {
		var certPool *x509.CertPool
		if pemfile := setting.KeystoneRootCAPEMFile; pemfile != "" {
			certPool = x509.NewCertPool()
			pemFileContent, err := ioutil.ReadFile(pemfile)
			if err != nil {
				panic(err)
			}
			if !certPool.AppendCertsFromPEM(pemFileContent) {
				log.Error(3, "Failed to load any certificates from Root CA PEM file %s", pemfile)
			} else {
				log.Info("Successfully loaded certificate(s) from %s", pemfile)
			}
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool,
				InsecureSkipVerify: !setting.KeystoneVerifySSLCert},
		}
		tr.Proxy = http.ProxyFromEnvironment

		client = &http.Client{Transport: tr}
		return client
	}
}
