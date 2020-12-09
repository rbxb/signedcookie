package main

import (
	"flag"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/rbxb/signedcookie"
)

var port string

func init() {
	flag.StringVar(&port, "port", ":8080", "The port to listen at.")
}

func main() {
	flag.Parse()
	http.HandleFunc("/", serve)
	log.Fatal(http.ListenAndServe(port, nil))
}

// Responds with a random number or the value stored in the client's cookie.
func serve(w http.ResponseWriter, req *http.Request) {
	if b, ok := signedcookie.DefaultSigner.Verify(req, "example"); ok {
		// If a cookie exists, send it back to the client
		w.Write(b)
	} else {
		// or generate a number and set it to a cookie.
		n := rand.Int()
		b := []byte(strconv.Itoa(n))
		signedcookie.DefaultSigner.SetCookie(w, "example", b, time.Now().Add(time.Hour))
		w.Write(b)
	}
}
