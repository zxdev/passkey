package main

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"time"

	"github.com/zxdev/passkey"
)

/*

	simple client example use case

	this example uses 15-second interval rotations to
	demonstrate that the rolling code cycles


*/

func main() {

	// a custom server interval was used, otherwise could just use
	// the passkey.NewClient(ctx,secret) method
	var interval = time.Second * 15
	var timeout = time.Second * 15

	var pk passkey.Client
	pk.Secret("PASSKEYXXBASE32XXSECRETXXEXAMPLE")
	pk.Interval(&interval)
	pk.Start(context.Background())

	var exit = 15
	for exit != 0 {

		client := &http.Client{Timeout: timeout}
		req, _ := http.NewRequest("GET", "http://localhost:8080/hello", nil)
		pk.SetHeader(req)
		resp, err := client.Do(req)
		if err != nil {
			log.Println(err)
			return
		}
		if resp.StatusCode != 200 {
			log.Println("http:", resp.StatusCode)
			return
		}

		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		log.Println(buf.String())

		time.Sleep(interval / 3)
		exit--
	}
}
