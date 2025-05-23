package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zxdev/passkey"
)

/*

	pkgen
	is a helper utility that will generate random shared sercrets
	as well a valid passkey codes based off of a valid base32
	encoded 32-character shared secret which can be utilized for
	command line testing or single interaction use cases; specify
	unique intervals in seconds or the default time.Minute is used

	% pkgen
	LMK3UEETD52M4EHZWAQ3CJHZ37OI3GQA

	% pkgen LMK3UEETD52M4EHZWAQ3CJHZ37OI3GQA
	GM3RCIQWPCJL4YAS

	% pkgen LMK3UEETD52M4EHZWAQ3CJHZ37OI3GQA 15
	ZOGFKOQPDOG5TI5S

	% curl -H token:$(pkgen AW6TJVTYMAYJXLWFW2WWJ6D3Q5B2AY25) http://localhost:8080/hello

	install pkgen on your machine
	go build -o /usr/local/bin cmd/main.go
*/

func main() {

	// configure secret
	var secret = os.Getenv("SECRET")
	if len(secret) == 0 && len(os.Args) == 1 {
		if u, err := user.Current(); err == nil {
			if f, err := os.Open(filepath.Join(u.HomeDir, ".pkgen")); err == nil {
				var b [32]byte
				f.Read(b[:])
				f.Close()
				secret = string(b[:])
			}
		}
	}

	if len(secret) == 0 && len(os.Args) > 1 {
		if strings.TrimPrefix(os.Args[1], "-") == "help" {
			fmt.Println("usage: pkgen                                    | emits {secret}")
			fmt.Println("usage: pkgen {secret} {seconds}                 | emits token")
			fmt.Println("usage: SECRET={secret} INTERVAL={seconds} pkgen | emits token")
			return
		}
		secret = os.Args[1]
	}

	// configure interval
	var interval time.Duration
	if n := os.Getenv("INTERVAL"); len(n) > 0 {
		i, _ := strconv.Atoi(n)
		interval = time.Duration(i) * time.Second
	}
	if interval == 0 && len(os.Args) > 2 {
		i, _ := strconv.Atoi(os.Args[2])
		interval = time.Duration(i) * time.Second
	}

	// configure passkey.CMD using the secret and interval and when
	// none are supplied a random secret will be generated
	pk := new(passkey.CMD)
	pk.Interval(&interval)
	current := pk.Current(secret)
	if len(secret) == 0 {
		fmt.Fprintln(os.Stdout, pk.Show())
		return
	}

	fmt.Fprintln(os.Stdout, current)
}
