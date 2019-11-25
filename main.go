package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/hashicorp/vault/api"
	salpem "github.com/salrashid123/signer/pem"
	//salkms "github.com/salrashid123/signer/kms"
	//saltpm "github.com/salrashid123/signer/tpm"
)

func main() {

	caCert, err := ioutil.ReadFile("certs/CA_crt.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r, err := salpem.NewPEMCrypto(&salpem.PEM{
		PublicCertFile: "certs/client.crt",
		RootCAs:        caCertPool,
		PublicPEMFile:  "certs/client.pem",
		PrivatePEMFile: "certs/client.key",
	})

	// r, err := salkms.NewKMSCrypto(&salkms.KMS{
	// 	PublicKeyFile: "certs/client.crt",
	// 	ProjectId:     "mineral-minutia-820",
	// 	LocationId:    "us-central1",
	// 	KeyRing:       "mycacerts",
	// 	Key:           "client",
	// 	KeyVersion:    "2",
	// 	RootCAs:       caCertPool,
	// })

	// r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
	// 	TpmDevice: "/dev/tpm0",
	// 	TpmHandle: 0x81010002,

	// 	PublicCertFile: "certs/client.crt",
	// 	RootCAs:        caCertPool,
	// })

	if err != nil {
		log.Println(err)
		return
	}

	tr := &http.Transport{
		TLSClientConfig: r.TLSConfig(),
	}

	config := &api.Config{
		Address:    "https://localhost:8200",
		HttpClient: &http.Client{Transport: tr},
	}

	hclient, err := api.NewClient(config)
	if err != nil {
		fmt.Println(err)
		return
	}

	hclient.SetToken("")
	data := map[string]interface{}{
		"name": "web",
	}
	c, err := hclient.Logical().Write("auth/cert/login", data)
	if err != nil {
		fmt.Println(err)
		return
	}

	tok, err := c.TokenID()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(tok)

}
