package main

import (
	"fmt"
	"log"

	"gitlab.com/schmorrison/goauth0/authentication"
)

func main() {
	fmt.Println("Starting go-auth0")

	ac := authentication.NewAuth0Client("PgBbhVe8a7AZYrXRkGnEoFWjxSxgd1KS", "https://schmorrison.auth0.com")

	k, err := ac.UserPasswordless("schmorrison@gmail.com", "link")
	if err != nil {
		log.Fatal(err)
	}
	if k {
		fmt.Println("K is true, email sent")
	}

	a, err := ac.UserPassSignin("schmorrison@gmail.com", "Qwer1234")
	if err != nil {
		log.Fatal(err)
	}

	up, err := ac.UserProfile(a["id_token"])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", up)
}
