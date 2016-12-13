package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

//Running NewAuth0Client is the first method to run
//Pass the parameters [ClientID], which is the Auth0ClientID and
//the Management account domain in the form of "https://[username].auth0.com"
func NewAuth0Client(ClientID string, ClientSecret string, Domain string) (*Auth0Client, error) {

	dmn, err := url.Parse(Domain)
	if err != nil {
		log.Fatal(err)
	}
	if dmn.Scheme == "http" {
		return nil, errors.New("Must define a scheme of https")
	}

	newCli := &Auth0Client{Domain: dmn, ClientID: ClientID, ClientSecret: ClientSecret}

	return newCli, nil
}

func (ac *Auth0Client) NewToken() error {
	url := ac.Domain.String() + "/oauth/token"

	p := strings.NewReader(fmt.Sprintf("{\"client_id\":\"%s\",\"client_secret\":\"%s\",\"audience\":\"%s/api/v2/\",\"grant_type\":\"client_credentials\"}", ac.ClientID, ac.ClientSecret, ac.Domain.String()))

	req, err := http.NewRequest("POST", url, p)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	var nt NewTokenPayload

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(body, &nt)
	if err != nil {
		log.Fatal(err)
	}
	token, err := jwt.Parse(nt.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(ac.ClientSecret), nil
	})
	ac.Token = token
	return nil
}
