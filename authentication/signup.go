package authentication

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

//UserPasswordSignup method for Auth0Client takes the desired username and password
//of a new user and returns a map string interface with the json response
func (ac *Auth0Client) UserPasswordSignup(Email string, Password string) (map[string]interface{}, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"dbconnections/signup")

	str := Auth0Payload{ClientID: ac.ClientID, //Generate the payload from domain and username/password
		Domain:     dmn,
		Email:      Email, //Requires Email rather than Username field
		Password:   Password,
		Connection: "Username-Password-Authentication"}

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
		return nil, fmt.Errorf("Invalid Request: %d", resp.StatusCode)
	}

	return rmp, fmt.Errorf("NewUser: %d", resp.StatusCode) //Did not catch failure
}

//EmailPasswordChange method for Auth0Client takes the desired email and password
//of a user and returns a success bool upon requesting a password reset for the user
func (ac *Auth0Client) EmailPasswordChange(Email string) (bool, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"dbconnections/change_password")

	str := Auth0Payload{ClientID: ac.ClientID, //Generate the payload from domain and username/password
		Domain:     dmn,
		Email:      Email, //The email entered will receive a Password Reset Email
		Connection: "Username-Password-Authentication"}

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
		return false, fmt.Errorf("Invalid Request: %d", resp.StatusCode)
	}
	return false, fmt.Errorf("Change Password Email: %v", resp.StatusCode)
}
