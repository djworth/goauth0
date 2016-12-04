package main

import (
	"fmt"
	"log"

	goauth0 "gitlab.com/schmorrison/goauth0/authentication"
)

var AUTH0_CLIENT_ID = ""

var AUTH0_DOMAIN = ""

func main() {
	fmt.Println("Starting go-auth0")

	ac := goauth0.NewAuth0Client(AUTH0_CLIENT_ID, AUTH0_DOMAIN)

	a, err := ac.UserPassSignin("exmaple@test.com", "Qwer1234")
	if err != nil {
		log.Fatal(err)
	}

	up, err := ac.UserProfileJWT(a["id_token"])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", up)
}
