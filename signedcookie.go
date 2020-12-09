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

const encodedLen = 44

// DefaultSigner is the default signer.
var DefaultSigner = NewSigner()

// Signer is used to sign and verify cookies.
type Signer struct {
	key []byte
	max int
}

// NewSigner creates a new Signer using an optional key.
// If no key is provided, a key will be randomly generated.
// Key will be padded or truncated to 44 bytes long.
func NewSigner(key ...[]byte) *Signer {
	signer := &Signer{}
	if len(key) == 0 {
		signer.key = make([]byte, encodedLen)
		if _, err := rand.Read(signer.key[:]); err != nil {
			log.Fatal(err)
		}
	} else {
		signer.key = key[0]
	}
	if x := len(signer.key); x > encodedLen {
		signer.max = x
	} else {
		signer.max = encodedLen
	}
	return signer
}

// SetCookie signs the data and sets a cookie to w with the name.
func (signer *Signer) SetCookie(w http.ResponseWriter, name string, data []byte, expires time.Time) {
	value := base64.URLEncoding.EncodeToString(signer.sign(data))
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
	return signer.verify(cookie.Value)
}

func (signer *Signer) sign(data []byte) []byte {
	p := len(data)
	b := make([]byte, p+signer.max)
	copy(b, data)
	copy(b[p:], signer.key[:])
	hash := sha256.Sum256(b[:p+len(signer.key)])
	base64.URLEncoding.Encode(b[p:], hash[:])
	return b[:p+encodedLen]
}

func (signer *Signer) verify(value string) ([]byte, bool) {
	if len(value) < encodedLen {
		return nil, false
	}
	p := len(value) - encodedLen
	b := make([]byte, p+signer.max)
	copy(b, value)
	var clientHash [32]byte
	base64.URLEncoding.Decode(clientHash[:], b[p:])
	copy(b[p:], signer.key[:])
	for i, x := range sha256.Sum256(b[:p+len(signer.key)]) {
		if x != clientHash[i] {
			return nil, false
		}
	}
	return b[:p], true
}
