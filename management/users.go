package management

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func (ac *Auth0Client) ListUsers() (users Users, err error) {
	dmn := ac.Domain.String() + "/api/v2/users"

	req, err := http.NewRequest("GET", dmn, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("content-type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", ac.Token.Raw))

	res, err := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(body, &users)
	if err != nil {
		log.Fatal(err)
	}

	return users, nil
}

func (ac *Auth0Client) UpdateUser(id string, p string) (u UserPayload, err error) {
	dmn := ac.Domain.String() + "/api/v2/users/" + id

	udm, err := url.Parse(dmn)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest("PATCH", udm.String(), strings.NewReader(p))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("content-type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", ac.Token.Raw))

	res, err := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(body, &u)
	if err != nil {
		log.Fatal(err)
	}

	return u, nil
}
