# passkey authentication

A simple authentication system for machine-to-machine communication utilizing a rolling interval based authentication code derived from a shared secret using the concept of RFC 4226 OTP standards.

###  The ```passkey/cmd``` and ```passkey/example``` folders have working examples.

For a working client-server example ```go run example/server/main.go``` and then ```go run example/client/main.go``` in a different terminal.

---

* **CMD wrapper** provides:
    * secret generation
    * code generation passkey generator for manual testing
        * ```go build cmd/pkgen.go``` is provided to obtain the current interval passkey 
        * token can be drived and utilized with curl from the shell via ```curl -H token:$(pkgen AW6TJVTYMAYJXLWFW2WWJ6D3Q5B2AY25) http://localhost:1455/demo```
    * install pkgen command line utility with ```sudo go build cmd/main.go -o /usr/local/bin/pkgen```

```golang
func main() {

	// configure secret
	var secret = os.Getenv("SECRET")
	if len(secret) == 0 && len(os.Args) > 1 {
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
```
---

* **Server wrapper** provides:
    * HKey setting
    * IsValid middleware

```golang
func getRoot(w http.ResponseWriter, r *http.Request) {
	log.Println("got / request")
	w.Write([]byte("try /hello"))
}

func getHello(w http.ResponseWriter, r *http.Request) {
	log.Println("got /hello request")
	w.Write([]byte("Hello!"))
}

func main() {

	var pk passkey.NewServer((context.Background(),"PASSKEYXXBASE32XXSECRETXXEXAMPLE")

	router := http.NewServeMux()
	router.Handle("/", http.HandlerFunc(getRoot))
	router.Handle("/hello", pk.IsValid(http.HandlerFunc(getHello)))

	http.ListenAndServe(":8080", router)

}


```
---
* **Client wrapper** provides:
    * Token generation

```golang
func main() {

	var timeout = time.Second * 15
	var pk passkey.NewClient(context.Background(),"PASSKEYXXBASE32XXSECRETXXEXAMPLE")

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

}
```