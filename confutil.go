/*
Package confutil contains utility types and functions which help with
configuration loading.
*/
package confutil

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

// TLS is a TLS certificate chain and private key.
type TLS tls.Certificate

// UnmarshalJSON unmarshals TLS from a {"chain": "string", "key": "string"}
// JSON object where
//
//   - "chain" contains the concatenated PEM-encodings of X.509 certificates
//     (leaf certificate first) and
//
//   - "key" the PEM-encoding of the PKCS #8 private key for the leaf.
//
func (t *TLS) UnmarshalJSON(data []byte) error {
	if noop(data) {
		return nil
	}

	var parsed struct {
		Chain string
		Key   string
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return errors.Wrap(err, "unmarshal TLS")
	}
	cert, err := tls.X509KeyPair([]byte(parsed.Chain), []byte(parsed.Key))
	if err != nil {
		return errors.Wrap(err, "parse TLS")
	}
	*t = TLS(cert)
	return nil
}

// Certificate is a single X.509 certificate.
type Certificate x509.Certificate

// UnmarshalJSON unmarshals Certificate from a JSON string containing the
// PEM-encoding of the X.509 certificate.
func (c *Certificate) UnmarshalJSON(data []byte) error {
	if noop(data) {
		return nil
	}

	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.Wrap(err, "unmarshal certificate")
	}
	block, rest := pem.Decode([]byte(raw))
	if block == nil {
		return errors.New("certificate not PEM-encoded")
	}
	if block.Type != "CERTIFICATE" {
		return errors.Errorf("not a certificate: %s", block.Type)
	}
	if len(block.Headers) > 0 {
		return errors.New("PEM headers not allowed")
	}
	if len(rest) > 0 {
		return errors.Errorf("certificate has %d trailing bytes", len(rest))
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.Wrap(err, "parse certificate")
	}
	*c = Certificate(*cert)
	return nil
}

// CertPool is a set of X.509 certificates.
type CertPool x509.CertPool

// UnmarshalJSON unmarshals CertPool from a JSON array of encoded Certificates.
func (p *CertPool) UnmarshalJSON(data []byte) error {
	if noop(data) {
		return nil
	}

	var certs []*Certificate
	if err := json.Unmarshal(data, &certs); err != nil {
		return errors.Wrap(err, "unmarshal certificates")
	}
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert((*x509.Certificate)(cert))
	}
	*p = CertPool(*pool)
	return nil
}

// URL is an absolute URL. It has the original string and a parsed structure.
type URL struct {
	Raw string
	URL *url.URL
}

// UnmarshalJSON unmarshals URL from a JSON string. The URL must be absolute.
func (u *URL) UnmarshalJSON(data []byte) error {
	if noop(data) {
		return nil
	}

	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.Wrap(err, "unmarshal URL")
	}
	if raw == "" { // Handle empty strings as unspecified.
		return nil
	}
	url, err := url.Parse(raw)
	if err != nil {
		return errors.Wrap(err, "parse URL")
	}

	if !url.IsAbs() || url.Host == "" { // Do not allow opaque URLs.
		return errors.Errorf("not an absolute URL: %s", raw)
	}

	u.Raw = raw
	u.URL = url
	return nil
}

// String returns the raw original URL string.
func (u *URL) String() string {
	return u.Raw
}

// Seconds is a time.Duration which is represented in configuration files as a
// whole number of seconds.
type Seconds time.Duration

// Or returns the time.Duration represented by s or def if s is zero.
func (s *Seconds) Or(def time.Duration) time.Duration {
	if *s > 0 {
		return time.Duration(*s)
	}
	return def
}

// UnmarshalJSON unmarshals Seconds from a JSON number.
func (s *Seconds) UnmarshalJSON(data []byte) error {
	if noop(data) {
		return nil
	}

	var duration time.Duration
	if err := json.Unmarshal(data, &duration); err != nil {
		return errors.Wrap(err, "unmarshal seconds")
	}
	*s = Seconds(duration * time.Second)
	return nil
}

// String returns the duration formatted as a string.
func (s Seconds) String() string {
	return time.Duration(s).String()
}

func noop(data []byte) bool {
	// Ignore null, required by interface definition.
	return string(data) == "null"
}
