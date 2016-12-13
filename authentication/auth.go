package authentication

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

//Running NewAuth0Client is the first method to run
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

//The UserPasswordSignup method for Auth0Client takes the desired username and password
//of a new user and returns a map string interface with the json response
func (ac *Auth0Client) UserPasswordSignup(Username string, Password string) (map[string]interface{}, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"dbconnections/signup")

	str := Auth0Payload{ClientID: ac.ClientID, //Generate the payload from domain and username/password
		Domain:     dmn,
		Email:      Username, //Requires Email rather than Username field
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
		return nil, errors.New(fmt.Sprintf("Invalid Request: %d", resp.StatusCode))
	}

	return rmp, errors.New(fmt.Sprintf("NewUser: %d", resp.StatusCode)) //Did not catch failure
}

//The EmailPasswordChange method for Auth0Client takes the desired email and password
//of a user and returns a success bool upon requesting a password reset for the user
func (ac *Auth0Client) EmailPasswordChange(Username string) (bool, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"dbconnections/change_password")

	str := Auth0Payload{ClientID: ac.ClientID, //Generate the payload from domain and username/password
		Domain:     dmn,
		Email:      Username, //The email entered will receive a Password Reset Email
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
		return false, errors.New(fmt.Sprintf("Invalid Request: %d", resp.StatusCode))
	}
	return false, errors.New(fmt.Sprintf("Change Password Email: %v", resp.StatusCode))
}

//The UserProfile method for Auth0Client takes the user IdToken
//of a user and returns a map[string]interface with the json response
//DOes not work, CANT FIGURE OUT THE GET REQUEST PARAMETERS
func (ac *Auth0Client) UserProfileAT(IdToken interface{}) (UserProfile, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"userinfo")

	//Userprofile from accesstoken uses a get request with no body and
	//the accessToken in the authorization header in form: "Bearer [accesstoken]"
	req, err := http.NewRequest("GET", dmn, bytes.NewBuffer([]byte("")))
	req.Header.Set("Authorization", fmt.Sprintf("%s", IdToken))

	client := &http.Client{}
	resp, err := client.Do(req) //Perform get request
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	var up UserProfile

	switch { //Switch should be moved to a helper
	case resp.StatusCode == 200: //value returned successfully
		ur, err := ioutil.ReadAll(resp.Body) //Read the response body
		if err != nil {
			log.Fatal(err)
		}
		err = json.Unmarshal(ur, &up) //Parse the body into the UserProfile variable defined above
		if err != nil {
			log.Fatal(err)
		}
		return up, nil
	case resp.StatusCode > 400 && resp.StatusCode < 500: //Request failed
		var rk UserProfile
		return rk, errors.New(fmt.Sprintf("Invalid Request: %d", resp.StatusCode))
	}
	return up, errors.New(fmt.Sprintf("Signin User: %v", resp.StatusCode))
}

//The UserProfile method for Auth0Client takes the user IdToken
//of a user and returns a map[string]interface with the json response
func (ac *Auth0Client) UserProfileJWT(IdToken interface{}) (UserProfile, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"tokeninfo")

	//Userprofile from JWT uses a post request with the JWT encoded as json in the field id_token
	//and written to the request body
	str := UserToken{IdToken: fmt.Sprintf(IdToken.(string))}
	jsn, err := json.Marshal(str) //Encode the usertoken as json

	req, err := http.NewRequest("POST", dmn, bytes.NewBuffer(jsn)) //Define http Request
	req.Header.Set("Content-Type", "application/json")             //Set http header as content type: json

	client := &http.Client{}
	resp, err := client.Do(req) //Perform POST request
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	var up UserProfile

	switch { //Switch should be moved to a helper
	case resp.StatusCode == 200: //value returned successfully
		ur, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		err = json.Unmarshal(ur, &up) //Parse the body into the UserProfile variable defined above
		if err != nil {
			log.Fatal(err)
		}
		return up, nil
	case resp.StatusCode > 400 && resp.StatusCode < 500: //Request failed
		var rk UserProfile
		return rk, errors.New(fmt.Sprintf("Invalid Request: %d", resp.StatusCode))
	}
	return up, errors.New(fmt.Sprintf("Signin User: %v", resp.StatusCode))
}
