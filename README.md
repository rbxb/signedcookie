# signedcookie
 
signedcookie is used to set and read cookies and verify that they were written by the server and are unmodified.

## Usage

Set a cookie:
```go
signedcookie.DefaultSigner.SetCookie(w, "example", data, time.Now().Add(time.Hour))
```

Read and verify a cookie:
```go
if data, ok := signedcookie.DefaultSigner.Verify(req, "example"); ok {
	// do something with data
}
```