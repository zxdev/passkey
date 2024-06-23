package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/zxdev/passkey"
)

/*

	simple server example use case

	this example uses 15-second interval rotations to
	demonstrate the rolling code cycles


*/

func getRoot(w http.ResponseWriter, r *http.Request) {
	log.Println("got / request")
	w.Write([]byte("try /hello"))
}

func getHello(w http.ResponseWriter, r *http.Request) {
	log.Println("got /hello request")
	w.Write([]byte("Hello!"))
}

func main() {

	// custom server interval otherwise could just use
	// the passkey.NewServer(ctx,secret) method
	var interval = time.Second * 15

	var pk passkey.Server
	pk.Secret("PASSKEYXXBASE32XXSECRETXXEXAMPLE")
	pk.Interval(&interval)
	pk.Start(context.Background())

	router := http.NewServeMux()
	router.Handle("/", http.HandlerFunc(getRoot))
	router.Handle("/hello", pk.IsValid(http.HandlerFunc(getHello)))

	http.ListenAndServe(":8080", router)

}
