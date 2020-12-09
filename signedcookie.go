// Package signedcookie is used to sign cookies using a secret stored
// on the server to ensure that a cookie value has not been modified.
package signedcookie

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net/http"
	"time"
)

// DefaultSigner is the default signer.
var DefaultSigner = NewSigner()

// Signer is used to sign and verify cookies.
type Signer struct {
	key []byte
	max int
}

// NewSigner creates a new Signer using an optional key.
// If no key is provided, a key will be randomly generated.
func NewSigner(key ...[]byte) *Signer {
	signer := &Signer{}
	if len(key) == 0 {
		signer.key = make([]byte, 32)
		if _, err := rand.Read(signer.key[:]); err != nil {
			log.Fatal(err)
		}
	} else {
		signer.key = key[0]
	}
	if x := len(signer.key); x > 32 {
		signer.max = x
	} else {
		signer.max = 32
	}
	return signer
}

// SetCookie signs the data and sets a cookie to w with the name.
// Signing a cookie also base64 encodes it.
func (signer *Signer) SetCookie(w http.ResponseWriter, name string, data []byte, expires time.Time) {
	value := base64.RawStdEncoding.EncodeToString(signer.sign(data))
	http.SetCookie(w, &http.Cookie{
		Name:    name,
		Value:   value,
		Expires: expires,
	})
}

// Verify checks the request's cookie for the Signer's signature.
// Verify returns true if the cookie is valid and unmodified.
func (signer *Signer) Verify(req *http.Request, name string) ([]byte, bool) {
	cookie, err := req.Cookie(name)
	if err != nil {
		return nil, false
	}
	b, err := base64.RawStdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, false
	}
	return signer.verify(b)
}

func (signer *Signer) sign(data []byte) []byte {
	p := len(data)
	b := make([]byte, p+signer.max)
	copy(b, data)
	copy(b[p:], signer.key)
	hash := sha256.Sum256(b[:p+len(signer.key)])
	copy(b[p:], hash[:])
	return b[:p+32]
}

func (signer *Signer) verify(b []byte) ([]byte, bool) {
	if len(b) < 32 {
		return nil, false
	}
	p := len(b) - 32
	clientHash := make([]byte, 32)
	copy(clientHash, b[p:])
	b = append(b[:p], signer.key...)
	hash := sha256.Sum256(b[:p+len(signer.key)])
	for i := range hash {
		if hash[i] != clientHash[i] {
			return nil, false
		}
	}
	return b[:p], true
}
