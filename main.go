package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"

	auth "gitlab.com/schmorrison/go-auth0/authentication"
	mgmt "gitlab.com/schmorrison/go-auth0/management"
)

func main() {
	fmt.Println("Starting go-auth0")
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	authtest()
	//mgmttest()
}

func mgmttest() {
	ac, err := mgmt.NewAuth0Client(os.Getenv("AUTH0_CLIENT_ID"), os.Getenv("AUTH0_CLIENT_SECRET"), os.Getenv("AUTH0_DOMAIN"))
	if err != nil {
		log.Fatal(err)
	}
	err = ac.NewToken()
	if err != nil {
		log.Fatal(err)
	}

	p := "{\"user_metadata\":{\"profileCode\":1479,\"addresses\":{\"work_address\":\"100 Industrial Way\",\"home_address\":\"742 Evergreen Terrace\"}}}"

	u, err := ac.UpdateUser("auth0|573e001a12c8df7018160ced", p)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", u)
}

func authtest() {
	ac, err := auth.NewAuth0Client(os.Getenv("AUTH0_CLIENT_ID"), os.Getenv("AUTH0_DOMAIN"))
	if err != nil {
		log.Fatal(err)
	}

	a, err := ac.UserPasswordSignin("schmorrison@gmail.com", "Qwer1234")
	if err != nil {
		log.Fatal(err)
	}

	up, err := ac.UserProfileAT(a["access_token"])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", up)
}
