package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"

	goauth0 "gitlab.com/schmorrison/goauth0/authentication"
)

func main() {
	fmt.Println("Starting go-auth0")
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	ac, err := goauth0.NewAuth0Client(os.Getenv("AUTH0_CLIENT_ID"), os.Getenv("AUTH0_DOMAIN"))
	if err != nil {
		log.Fatal(err)
	}

	a, err := ac.UserPasswordSignin("schmorrison@gmail.com", "Qwer1234")
	if err != nil {
		log.Fatal(err)
	}

	up, err := ac.UserProfileJWT(a["id_token"])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", up)
}
