package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	tara "github.com/e-gov/TARA-Go"
)

func main() {
	client, err := tara.NewClient(tara.Conf{
		Issuer:                "https://tara-test.ria.ee",
		AuthorizationEndpoint: "https://tara-test.ria.ee/oidc/authorize",
		TokenEndpoint:         "https://tara-test.ria.ee/oidc/token",
		JWKSURI:               "https://tara-test.ria.ee/oidc/jwks",
		RedirectionURI:        "",
		ClientIdentifier:      "",
		ClientSecret:          "",
		Scope:                 []string{"idcard", "mid", "smartid"},
		RequestLogger:         log.New(os.Stdout, "tara: ", log.LstdFlags),
	})
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := client.AuthenticationRequest(w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	http.HandleFunc("/path/to/redirect", func(w http.ResponseWriter, r *http.Request) {
		token, err := client.AuthenticationResponse(r)
		if err != nil {
			status := http.StatusInternalServerError
			if _, ok := err.(tara.BadRequestError); ok {
				status = http.StatusBadRequest
			}
			http.Error(w, err.Error(), status)
			return
		}
		client.ClearCookies(w)
		fmt.Fprintf(w, "%+v", token)
	})
	log.Fatal(http.ListenAndServeTLS(":8000", "localhost.pem", "localhost.key", nil))
}
