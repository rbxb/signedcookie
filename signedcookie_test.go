package signedcookie

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestDefaultSigner(t *testing.T) {
	testVerify(t, DefaultSigner)
}

func TestCustomKeyShort(t *testing.T) {
	var b [4]byte
	rand.Read(b[:])
	testVerify(t, NewSigner(b[:]))
}

func TestCustomKeyLong(t *testing.T) {
	var b [200]byte
	rand.Read(b[:])
	testVerify(t, NewSigner(b[:]))
}

func testVerify(t *testing.T, signer *Signer) {
	text := "hello"
	b := signer.sign([]byte(text))

	if data, ok := signer.verify(string(b)); !ok {
		t.Errorf("Failed verify on unmodified value.")
	} else if string(data) != text {
		t.Errorf("Failed verify getting text. " + string(data))
	}

	b = append([]byte("test"), b[:len(b)-32]...)
	if _, ok := signer.verify(string(b)); ok {
		t.Errorf("Failed verify on modified value.")
	}

	fakehash := sha256.Sum256(b)
	s := base64.URLEncoding.EncodeToString(fakehash[:])
	b = append(b, []byte(s)...)
	if _, ok := signer.verify(string(b)); ok {
		t.Errorf("Failed verify on fake hash.")
	}
}
