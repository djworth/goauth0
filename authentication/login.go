package authentication

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

//login.go includes the following USER login methods:
/*
ac.UserPasswordSignin(Username string, Password string)(map[string]interface{}, error)
ac.EmailPasswordless(Username string, proto string) (bool, error)
//NOT IMPLEMENTED
ac.UserSocialSignin()()
*/

//The UserPasswordSignin method for Auth0Client takes the username and password
//of a user and returns a map[string]interface with the json response
func (ac *Auth0Client) UserPasswordSignin(Username string, Password string) (map[string]interface{}, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"oauth/ro")

	str := Auth0Payload{ClientID: ac.ClientID, //Generate the payload from domain and username/password
		Domain:     dmn,
		Username:   Username, //Signin requires the username which may be the same email
		Password:   Password,
		Connection: "Username-Password-Authentication",
		GrantType:  "password",
		Scope:      "openid name email"}

	jsn, err := json.Marshal(str) //Encode Payload as JSON

	req, err := http.NewRequest("POST", dmn, bytes.NewBuffer(jsn)) //Define http Request
	req.Header.Set("Content-Type", "application/json")             //Set http header as content type: json

	client := &http.Client{}
	resp, err := client.Do(req) //Perform get request
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	rmp, err := MapAuth0Response(resp) //Map the response body to map[string]interface{}
	if err != nil {
		return rmp, err
	}

	switch { //Switch should be moved to a helper
	case resp.StatusCode == 200: //value returned successfully
		return rmp, nil
	case resp.StatusCode > 400 && resp.StatusCode < 500: //Request failed
		return nil, errors.New(fmt.Sprintf("Invalid Request: %d", resp.StatusCode))
	}

	return rmp, errors.New(fmt.Sprintf("Signin User: %v", resp.StatusCode))
}

//The UserPasswordless method for Auth0Client takes the username and a proto "code"/"link"
//for a user and returns a bool of whether the passwordless email was sent
func (ac *Auth0Client) EmailPasswordless(Username string, proto string) (bool, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"passwordless/start")

	str := Auth0Payload{ClientID: ac.ClientID, //Generate the payload from domain and username/password
		Email:      Username, //Email address to start passwordless flow
		Connection: "email",
		Send:       proto} //Proto should be code to use code as password in method ac.UserPasswordSignin([email],[code])

	jsn, err := json.Marshal(str) //Encode Payload as JSON

	req, err := http.NewRequest("POST", dmn, bytes.NewBuffer(jsn)) //Define http Request
	req.Header.Set("Content-Type", "application/json")             //Set http header as content type: json

	client := &http.Client{}
	resp, err := client.Do(req) //Perform get request
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	switch { //Switch should be moved to a helper
	case resp.StatusCode == 200: //value returned successfully
		return true, nil
	case resp.StatusCode > 400 && resp.StatusCode < 500: //Request failed
		return false, errors.New(fmt.Sprintf("Invalid Request: %d", resp.StatusCode))
	}

	return false, errors.New(fmt.Sprintf("Signin User: %v", resp.StatusCode))
}

//The UserSocialSignin method for Auth0Client takes the access token from a service provider and
// a string with the name of the service provider, eg. "facebook", "twitter", "weibo", "google-oauth2"
/*
func (ac *Auth0Client) UserSocialSignin(accessToken string, connection string) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"oauth/access_token")

	str := Auth0Payload{ClientID: ac.ClientID, //Generate the payload from domain and username/password
		AccessToken: accessToken,         //social providers access token
		Connection:  connection,          //name of social provider
		Scope:       "openid name email"} //Proto should be code to use code as password in method ac.UserPasswordSignin([email],[code])

	jsn, err := json.Marshal(str) //Encode Payload as JSON

	req, err := http.NewRequest("POST", dmn, bytes.NewBuffer(jsn)) //Define http Request
	req.Header.Set("Content-Type", "application/json")             //Set http header as content type: json

	client := &http.Client{}
	resp, err := client.Do(req) //Perform get request
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	switch { //Switch should be moved to a helper
	case resp.StatusCode == 200: //value returned successfully
		return true, nil
	case resp.StatusCode > 400 && resp.StatusCode < 500: //Request failed
		return false, errors.New(fmt.Sprintf("Invalid Request: %d", resp.StatusCode))
	}

	return false, errors.New(fmt.Sprintf("Signin User: %v", resp.StatusCode))
}
*/
