package passkey

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

/*

	PASSKEY
	generates a rolling set of authention codes based on a specified
	interval retaining the current, next, and previous that uses a
	shared secret between the server and client

*/

// PassKey generats a time based authentication token set based using a shared
// secret and a defined interval rolling authentication code generation ttl
type PassKey struct {
	interval time.Duration    // defaults to one-minute
	secret   [20]byte         // binary form of base32 secret; [A..Z,2..7]
	cnp      [3]atomic.Uint64 // valid token set; past,current,furture
}

// Interval sets the PassKey generation interval; default time.Minute
func (pk *PassKey) Interval(interval *time.Duration) *PassKey {

	if interval == nil || *interval == 0 {
		v := time.Minute
		interval = &v
	}
	pk.interval = *interval

	return pk
}

// Secret sets the PassKey secret; accepts
//
//	[20]byte secret
//	32-character base32 encoded string secret; [A..Z,2..7]
func (pk *PassKey) Secret(secret interface{}) *PassKey {

	switch v := secret.(type) {
	case string:
		if len(v) == 32 {
			b, err := base32.StdEncoding.DecodeString(v)
			if err != nil || len(v) != 32 {
				return nil
			}
			copy(pk.secret[:], b)
		}

	case [20]byte:
		copy(pk.secret[:], v[:])
	}

	return pk
}

// Start token generator using the secret and interval or apply
// default values when neither are configured; when a secret is
// generated the secret in use will be emited on os.Stdout
func (pk *PassKey) Start(ctx context.Context) {

	// default interval
	if pk.interval == 0 {
		pk.Interval(nil)
	}

	// validate secret; or failover and generate new secret and emit
	if bytes.Equal(pk.secret[:20], make([]byte, 20)) {
		rand.Read(pk.secret[:])
		fmt.Fprintln(os.Stdout, base32.StdEncoding.EncodeToString(pk.secret[:]))
	}

	// generate token set
	pk.generate(0) // current
	pk.generate(1) // next
	//pk.generate(2) // previous

	// configure interval generator
	ticker := time.NewTicker(pk.interval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				pk.cnp[2].Store(pk.cnp[0].Load()) // current -> previous
				pk.cnp[0].Store(pk.cnp[1].Load()) // next -> current
				pk.generate(1)                    // next

			}
		}
	}()

}

// generate the token requeste
//
//	0: current
//	1: next
//	2: previous
func (pk *PassKey) generate(i int) {

	// generate int64 unix time as a slice of bytes
	var bs [8]byte // int64 time bytes
	binary.LittleEndian.PutUint64(bs[:], uint64(
		time.Now().UTC().Add(time.Duration(i-1)*pk.interval).Round(pk.interval).Unix(),
	))

	// sign time slice bytes with the secret using hmac sha1 to
	// generate a unique reproduceable bytes slice hash
	sign := hmac.New(sha1.New, pk.secret[:])
	sign.Write(bs[:])
	hash := sign.Sum(nil)

	// use the last nibble (a half-byte) to choose the start index since this value
	// is at most 0xF (decimal 15), and there are 20 bytes of SHA1; we need 8 bytes
	// for Uint64 from hash starting from n index
	nibble := ((hash[19] & 0xf) / 2) + 1
	pk.cnp[i].Store(binary.LittleEndian.Uint64(hash[nibble : nibble+8]))

}

/*

	SERVER
	wrapper for PassKey with addition server methods

*/
// NewServer configurator takes a shared secret; applies defaults and will generate and
// emit a new secret on os.Stdout when required, and starts the interval generator
func NewServer(ctx context.Context, secret string) *Server {
	var server = new(Server)
	server.Secret(secret)
	server.Start(ctx)
	return server
}

// Server methods
type Server struct {
	PassKey
	hKey string // header token key name
}

// SetHeaderKey sets the http.Request header key that the
// IsValid middleware used to read r.Header.Get(pk.hKey)
func (pk *Server) SetHeaderKey(hkey string) *Server {
	pk.hKey = hkey
	return pk
}

// IsValid returns a http.Handler middleware for authentication; the
// default hKey {token} is set when necessary
func (pk *Server) IsValid(next http.Handler) http.Handler {

	if len(pk.hKey) == 0 {
		pk.hKey = "token" // default
	}

	// IsValid middleware validates the current header key:{value} for access or
	// aborts with a http.StatusUnauthorized response
	//return func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		b, err := base32.StdEncoding.DecodeString(r.Header.Get(pk.hKey))
		if err != nil || len(b) != 10 {
			w.WriteHeader(http.StatusBadRequest) // 400
			return
		}

		// ignore random ofuscation bits
		switch binary.LittleEndian.Uint64(b[:8]) {
		case pk.cnp[0].Load():
		case pk.cnp[1].Load():
		case pk.cnp[2].Load():
		default:
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)

	})

}

/*

	CLIENT
	wrapper for PassKey with addition client methods

*/

// NewClient configurator takea a shared secret; applies defaults and will generate and
// emit a new secret on os.Stdout when required, and starts the interval generator
func NewClient(ctx context.Context, secret string) *Client {

	client := new(Client)
	client.SetHeaderKey(nil)
	client.Secret(secret)
	client.Start(ctx)
	return client
}

// Client methods
type Client struct {
	PassKey
	hKey string
}

// SetHeaderKey sets the http.Request header key value that
// calling Current(*http.Request) sets as token value; nil for default
func (pk *Client) SetHeaderKey(hkey *string) *Client {
	if hkey == nil || len(*hkey) == 0 {
		pk.hKey = "token"
	} else {
		pk.hKey = *hkey
	}
	return pk
}

// SetHeader sets the req.Header key:{current} value
func (pk *Client) SetHeader(req *http.Request) {

	var b [10]byte
	rand.Read(b[8:]) // add random obfuscation bits
	binary.LittleEndian.PutUint64(b[:], pk.cnp[0].Load())
	req.Header.Set(pk.hKey, base32.StdEncoding.EncodeToString(b[:]))

}

/*

	COMMAND LINE
	wrapper for PassKey command line utilty without
	the interval generator; only provide current now

*/

// Client methods
type CMD struct {
	PassKey
}

// Show returns the base32 encoded shared secret
func (pk *CMD) Show() string {
	return base32.StdEncoding.EncodeToString(pk.secret[:])
}

// Current returns a current valid token based on the shared secret
func (pk *CMD) Current(secret string) string {

	// default interval
	if pk.interval == 0 {
		pk.Interval(nil)
	}

	pk.Secret(secret)

	// validate secret; or failover and generate
	if bytes.Equal(pk.secret[:20], make([]byte, 20)) {
		rand.Read(pk.secret[:])
	}

	// generate current token
	pk.generate(0) // current

	var b [10]byte
	rand.Read(b[8:]) // add random obfuscation bits
	binary.LittleEndian.PutUint64(b[:], pk.cnp[0].Load())
	return base32.StdEncoding.EncodeToString(b[:])
}
