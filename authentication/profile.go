package authentication

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

//UserProfileAT method for Auth0Client takes the user IdToken
//of a user and returns a map[string]interface with the json response
//DOes not work, CANT FIGURE OUT THE GET REQUEST PARAMETERS
func (ac *Auth0Client) UserProfileAT(AccessToken interface{}) (UserProfile, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"userinfo")

	//Userprofile from accesstoken uses a get request with no body and
	//the accessToken in the authorization header in form: "Bearer [accesstoken]"
	req, err := http.NewRequest("GET", dmn, bytes.NewBuffer([]byte("")))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", AccessToken))

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
		return rk, fmt.Errorf("Invalid Request: %d", resp.StatusCode)
	}
	return up, fmt.Errorf("Signin User: %v", resp.StatusCode)
}

//UserProfileJWT method for Auth0Client takes the user IdToken
//of a user and returns a map[string]interface with the json response
//TBD: Deprecation NOTICE TO BE POSTED
func (ac *Auth0Client) UserProfileJWT(IDToken interface{}) (UserProfile, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", //Generate a URL from saved URL values
		ac.Domain.Scheme,
		ac.Domain.Host,
		ac.Domain.Path,
		"tokeninfo")

	//Userprofile from JWT uses a post request with the JWT encoded as json in the field id_token
	//and written to the request body
	str := UserToken{IdToken: fmt.Sprintf(IDToken.(string))}
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
		return rk, fmt.Errorf("Invalid Request: %d", resp.StatusCode)
	}
	return up, fmt.Errorf("Signin User: %v", resp.StatusCode)
}
