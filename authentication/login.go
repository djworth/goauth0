package authentication

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

//UserPasswordSignin method for Auth0Client takes the username and password
//of a user and returns a map[string]interface with the json response
func (ac *Auth0Client) UserPasswordSignin(Username string, Password string) (map[string]interface{}, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"oauth/ro") //TBD: Deprecation notice to be posted
	//Update to oauth/token for future

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
		return nil, fmt.Errorf("Invalid Request: %d", resp.StatusCode)
	}

	return rmp, fmt.Errorf("Signin User: %v", resp.StatusCode)
}

//EmailPasswordless method for Auth0Client takes the username and a proto "code"/"link"
//for a user and returns a bool of whether the passwordless email was sent
func (ac *Auth0Client) EmailPasswordless(Username string, proto string) (map[string]interface{}, error) {
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

	rmp, err := MapAuth0Response(resp) //Map the response body to map[string]interface{}
	if err != nil {
		return rmp, err
	}

	switch { //Switch should be moved to a helper
	case resp.StatusCode == 200: //value returned successfully
		return rmp, nil
	case resp.StatusCode > 400 && resp.StatusCode < 500: //Request failed
		return rmp, fmt.Errorf("Invalid Request: %d", resp.StatusCode)
	}

	return rmp, fmt.Errorf("Signin User: %v", resp.StatusCode)
}

//SMSPasswordless method for Auth0Client takes the username and a proto "code"/"link"
//for a user and returns a bool of whether the passwordless sms was sent
func (ac *Auth0Client) SMSPasswordless(Phone string, proto string) (map[string]interface{}, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"passwordless/start")

	str := Auth0Payload{ClientID: ac.ClientID, //Generate the payload from domain and username/password
		Phone:      Phone, //Phone number to start passwordless flow
		Connection: "sms",
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

	rmp, err := MapAuth0Response(resp) //Map the response body to map[string]interface{}
	if err != nil {
		return rmp, err
	}

	switch { //Switch should be moved to a helper
	case resp.StatusCode == 200: //value returned successfully
		return rmp, nil
	case resp.StatusCode > 400 && resp.StatusCode < 500: //Request failed
		return rmp, fmt.Errorf("Invalid Request: %d", resp.StatusCode)
	}

	return rmp, fmt.Errorf("Signin User: %v", resp.StatusCode)
}

//AuthenticatePasswordless is used to authenticate the password
//received by the user via a passwordless signin method
//requires the connection method, the username identity, and the users one-time-password
func (ac *Auth0Client) AuthenticatePasswordless(c string, u string, p string) (map[string]interface{}, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"oauth/ro") //TBD: Deprecation notice to be posted
	//Update to oauth/token for future

	str := Auth0Payload{ClientID: ac.ClientID, //Generate the payload from domain and username/password
		Connection: c, //sms or email
		Username:   u, //phone_number if sms, email_address if email
		GrantType:  "password",
		Password:   p,
		Scope:      "openid"} //default to jwt, scope options should be addressed later

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
		return rmp, fmt.Errorf("Invalid Request: %d", resp.StatusCode)
	}

	return rmp, fmt.Errorf("Signin User: %v", resp.StatusCode)
}
