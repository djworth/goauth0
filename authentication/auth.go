package authentication

import (
	"errors"
	"log"
	"net/url"
)

//NewAuth0Client is the first method to run
//Pass the parameters [ClientID], which is the Auth0ClientID and
//the Management account domain in the form of "https://[username].auth0.com"
func NewAuth0Client(ClientID string, Domain string) (*Auth0Client, error) {

	dmn, err := url.Parse(Domain)
	if err != nil {
		log.Fatal(err)
	}
	if dmn.Scheme == "http" {
		return nil, errors.New("Must define a scheme of https")
	}

	newCli := &Auth0Client{Domain: dmn, ClientID: ClientID}

	return newCli, nil
}
