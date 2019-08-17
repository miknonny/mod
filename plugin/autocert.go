/**

    "Modlishka" Reverse Proxy.

    Copyright 2018 (C) Piotr Duszyński piotr[at]duszynski.eu. All rights reserved.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    You should have received a copy of the Modlishka License along with this program.

**/

package plugin

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/drk1wi/Modlishka/config"
	"github.com/drk1wi/Modlishka/log"
)

// Paste your CA certificate and key in the following format
// Ref: https://github.com/drk1wi/Modlishka/wiki/Quickstart-tutorial

const CA_CERT = `-----BEGIN CERTIFICATE-----
MIIDhjCCAm4CCQDQfdQgh67r0jANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAk5ZMQ4wDAYDVQQHDAVxdWVlbjEOMAwGA1UECgwFSmFtZXMx
CjAIBgNVBAsMAUoxHjAcBgNVBAMMFWxvb3BiYWNrLm1vZGxpc2hrYS5pbzEcMBoG
CSqGSIb3DQEJARYNdGVzdEB0ZXN0LmNvbTAeFw0xOTA4MTQxMTUwMDRaFw0yMjA2
MDMxMTUwMDRaMIGEMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTlkxDjAMBgNVBAcM
BXF1ZWVuMQ4wDAYDVQQKDAVKYW1lczEKMAgGA1UECwwBSjEeMBwGA1UEAwwVbG9v
cGJhY2subW9kbGlzaGthLmlvMRwwGgYJKoZIhvcNAQkBFg10ZXN0QHRlc3QuY29t
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7ZRe3EnQOGL8eyqD9YVb
LkeHEIDJnc+ke7luIYMmBD3RVPMeuExecWYIgW2w2WwN9tLRpG5GofAJdkNWv45T
eCv1UvWC0wygZWZQO3V8dhTnZ0N9U8dQ1wBsh5S8A6Qd4yJeM5s9DWt0oj6xTXgF
I9YTOXYhwhjyKZqA6xUGquevMSGvA6IiZfKcMsw4CURe2nHZqtOApVdZGyA7a8Ox
eBd16f9rKLjlrI62L49v9WYYWat7z2Qec9wN2Vvd2iDi6ufKkT2t+uEOPX5rE2Ws
UNyjeGgNMtiIRHSXrV5iMy1lymLi66WsoD3OcXO76lYaHC2PYPjwrZe/HdJwyZOV
QQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQDacS0Gljhyee6I77EEcuyxZ9d7pANm
Vuh/42oYwklVR2BK/nDSmP1arogf5waqvITgci/0H/l3t7X0Deh7P+mrqPJVElu2
kbaZTGPgIgqAzBykw9rD7fAL+1WwUuQ4yrJATqIXlyLYbzOWJ2IB2x0Wpmd0F5Qm
sdriyW5Qb3KyH/Kgbg0q0tRq4bawmATiZU81V5BbtdrLbyrQ51hsK8EoNhSG4Nr8
PEvlUUYQG52YWGhiqxcULSiAY7Z5hz8pDKhF7hCnihKEQy1Au50Vo1c4uVvPVHPK
qIz8ibBjujXDx+Vm1bdKFqVrCxi6fRJb3jVI1XN0GUrcSNMtFLurF2yi
-----END CERTIFICATE-----
`

const CA_CERT_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA7ZRe3EnQOGL8eyqD9YVbLkeHEIDJnc+ke7luIYMmBD3RVPMe
uExecWYIgW2w2WwN9tLRpG5GofAJdkNWv45TeCv1UvWC0wygZWZQO3V8dhTnZ0N9
U8dQ1wBsh5S8A6Qd4yJeM5s9DWt0oj6xTXgFI9YTOXYhwhjyKZqA6xUGquevMSGv
A6IiZfKcMsw4CURe2nHZqtOApVdZGyA7a8OxeBd16f9rKLjlrI62L49v9WYYWat7
z2Qec9wN2Vvd2iDi6ufKkT2t+uEOPX5rE2WsUNyjeGgNMtiIRHSXrV5iMy1lymLi
66WsoD3OcXO76lYaHC2PYPjwrZe/HdJwyZOVQQIDAQABAoIBAQCDpITzl0rzE5ZH
QQWhk+U0PZoPgO02rom7rMHje+Ii04YchiJtiJOETj9ESF2H/CG4tJRJgnlM3c7A
Ywu8VMbXfbQP5c4513NA/HJUoAL5Axg91d2qAHVAzRFWBwovEk8lPjPocIph1zrn
c8mW3XwroUFBw71s6Zm1h9ELcbkiFPFZt/iOUnlqpFRrDS9kOR24A4MTX+e1Yla7
CmiBJY2pORSNVOuTBC3zaV6KTqvC4oOxkR/HXJlerUEsFq8NVsDvpHEP89Se7LCb
xpHoR0CHFaYISOnInveBwMKHXCMWOnvJ5jeW1q7YyRkNgvtSmKDUDRbm5zELs0hW
tCssIdeJAoGBAPtKgY75kgQpB8AMNyg/BLDf8SgYN2fF3EmhvkywQzwkJ3vlK770
T+nmJqDREVTui4wQtnJ7o2wU8D+kSbdGjD67+1vJa/2Hye1PX58sZi1KBjyLQXCK
i1tslcRL7oXkoW5OE8N5vdsmZuczTGKVTBcQN9fS+PeCR0wBHr1rpc77AoGBAPII
FnjnoBZc2p/PcAiwLPhmhb9iOnPGm/s7ZOy/YPDYjLgzX0bqi77TrcMlA/o4kNGn
F5HyBzdNtzPIbFJIs26hroSaeDm6haCxuZSK75YpREFoo7Mw+WkgZSIU7gR5FlKQ
YuhdqDgCZ7fAkkzJbcEHfa70RnETtbXNOI8H8cfzAoGBAIBN/HS57Nn+8RwXoJoG
AykkToeARdnQZreZxAZ4APxWIWrbCkkHiT4N6y81UDojSlELv3wYsMpgroJwKctQ
VA88AA1PfLoIeQuX+WTWUJ1TLHgBSjpiIuFdQeLmOjVXFS2y49hs8olQxD3MLXYw
cJdeCoVCDSii9jBSahWhPxm9AoGBAKb6SXa0Zk/HU9V5aZO05/Gf2ZpGDImfdjGH
soNbLWg8Hile19a3Lh5DL9g4C1xv9gmOO8amsa/H4CLLnV/PZGtpBFvbriI1usc4
lg4TJGP2qG5v4LBZk1ihzuQKiINxfqMLlhE1vD6X+jJdmxF6zkuj/WPch1SwAmcg
5GpZUsddAoGAZPcqdWVG4ALvMY4JzRwyTh4kLkYTQVvktMWYor5Rt8bNNECCnVwY
rtHf+IvpqUxf5S1cv56ytFuOAGU8UUNa0BM19TRh4stL4R+kfINB8FOprwot5V17
Xj6KwUp4doT2B7mAf+YN2WCTh0dT5gOa7ZTJKdBMQPNL4+3Iu7jjHNQ=
-----END RSA PRIVATE KEY-----
`

func init() {

	s := Property{}

	s.Name = "autocert"
	s.Version = "0.1"
	s.Description = "This plugin is used to auto generate certificate for you . Really useful for testing different configuration flags against your targets. "

	s.Flags = func() {

		if *config.C.ForceHTTP == false {
			if len(*config.C.TLSCertificate) == 0 && len(*config.C.TLSKey) == 0 {

				log.Infof("Autocert plugin: Auto-generating %s domain TLS certificate", *config.C.ProxyDomain)

				CAcert := CA_CERT
				CAkey := CA_CERT_KEY

				catls, err := tls.X509KeyPair([]byte(CAcert), []byte(CAkey))
				if err != nil {
					panic(err)
				}
				ca, err := x509.ParseCertificate(catls.Certificate[0])
				if err != nil {
					panic(err)
				}

				var n int32
				binary.Read(rand.Reader, binary.LittleEndian, &n)

				template := &x509.Certificate{
					IsCA:                  false,
					BasicConstraintsValid: true,
					SubjectKeyId:          []byte{1, 2, 3},
					SerialNumber:          big.NewInt(int64(n)),
					DNSNames:              []string{*config.C.ProxyDomain, "*." + *config.C.ProxyDomain},
					Subject: pkix.Name{
						Country:      []string{"Earth"},
						Organization: []string{"Mother Nature"},
						CommonName:   *config.C.ProxyDomain,
					},
					NotBefore: time.Now(),
					NotAfter:  time.Now().AddDate(5, 5, 5),
				}

				// generate private key
				privatekey, err := rsa.GenerateKey(rand.Reader, 2048)

				if err != nil {
					log.Errorf("Error generating key: %s", err)
				}
				var privateKey = &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(privatekey),
				}

				//dump
				buf := new(bytes.Buffer)
				pem.Encode(buf, privateKey)
				tlskeyStr := buf.String()
				config.C.TLSKey = &tlskeyStr
				log.Debugf("AutoCert plugin generated TlsKey:\n %s", *config.C.TLSKey)

				// generate self signed cert
				publickey := &privatekey.PublicKey

				// create a self-signed certificate. template = parent
				//var parent = template
				var parent = ca

				cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, catls.PrivateKey)

				buf = new(bytes.Buffer)
				pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

				tlscertStr := buf.String()
				config.C.TLSCertificate = &tlscertStr
				log.Debugf("AutoCert plugin generated TlsCert:\n %s", *config.C.TLSCertificate)

				//the cert is auto-generated anyway
				*config.C.TLSPool = ""

				if err != nil {
					log.Errorf("Error creating certificate: %s", err)
				}

			}
		}

	}

	// Register all the function hooks
	s.Register()
}
