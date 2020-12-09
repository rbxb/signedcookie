package signedcookie

import (
	"crypto/sha256"
	"testing"
)

func TestVerify(t *testing.T) {
	text := "hello"
	b := DefaultSigner.sign([]byte(text))

	if data, ok := DefaultSigner.verify(b); !ok {
		t.Errorf("Failed verify on unmodified value.")
	} else if string(data) != text {
		t.Errorf("Failed verify getting text. " + string(data))
	}

	b = append([]byte("test"), b[:len(b)-32]...)
	if _, ok := DefaultSigner.verify(b); ok {
		t.Errorf("Failed verify on modified value.")
	}

	fakeHash := sha256.Sum256(b)
	b = append([]byte("hello"), fakeHash[:]...)
	if _, ok := DefaultSigner.verify(b); ok {
		t.Errorf("Failed verify on fake hash.")
	}
}
