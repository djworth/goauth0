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

type Auth0Client struct {
	ClientID string
	Domain   *url.URL
}

type Auth0Payload struct {
	ClientID   string `json:"client_id,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Email      string `json:"email,omitempty"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Connection string `json:"connection,omitempty"`
	GrantType  string `json:"grant_type,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Send       string `json:"send,omitempty"`
}

type UserProfile struct {
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	ClientID          string `json:"clientID"`
	UpdatedAt         string `json:"updated_at"`
	Picture           string `json:"picture"`
	UserId            string `json:"user_id"`
	Name              string `json:"name"`
	Nickname          string `json:"nickname"`
	Identities        []Identities
	CreatedAt         string `json:"created_at"`
	LastPasswordReset string `json:"last_password_reset"`
	GlobalClientId    string `json:"global_client_id"`
}

type Identities struct {
	UserId     string `json:"user_id"`
	Provider   string `json:"provider"`
	Connection string `json:"connection"`
	IsSocial   bool   `json:"isSocial"`
}

//Running NewAuth0Client is the first method to run
//Pass the parameters [ClientID], which is the Auth0ClientID and
//the Management account domain in the form of "https://[username].auth0.com"
func NewAuth0Client(ClientID string, Domain string) *Auth0Client {

	dmn, err := url.Parse(Domain)
	if err != nil {
		log.Fatal(err)
	}

	newCli := &Auth0Client{Domain: dmn, ClientID: ClientID}

	fmt.Println("Created new auth0 client...")
	return newCli
}

//The UserPassSignup method for Auth0Client takes the desired username and password
//of a new user and returns a map string interface with the json response
func (ac *Auth0Client) UserPassSignup(Username string, Password string) (map[string]interface{}, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", ac.Domain.Scheme, ac.Domain.Host, ac.Domain.Path, "dbconnections/signup")

	str := Auth0Payload{ClientID: ac.ClientID, Domain: dmn, Email: Username, Password: Password, Connection: "Username-Password-Authentication"}

	jsn, err := json.Marshal(str)

	req, err := http.NewRequest("POST", dmn, bytes.NewBuffer(jsn))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	rmp, err := MapAuth0Response(resp)
	if err != nil {
		return rmp, err
	}

	if resp.StatusCode == 200 {
		fmt.Println("   ...Created new user with password")
		return rmp, nil
	}
	if resp.StatusCode == 400 {
		return nil, errors.New("Invalid Request")
	}
	return rmp, errors.New(fmt.Sprintf("NewUser: %v", resp.StatusCode))
}

//The UserPassSignin method for Auth0Client takes the username and password
//of a new user and returns a map[string]interface with the json response
func (ac *Auth0Client) UserPassSignin(Username string, Password string) (map[string]interface{}, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", ac.Domain.Scheme, ac.Domain.Host, ac.Domain.Path, "oauth/ro")

	str := Auth0Payload{ClientID: ac.ClientID, Domain: dmn, Username: Username, Password: Password, Connection: "Username-Password-Authentication", GrantType: "password", Scope: "openid name email"}

	jsn, err := json.Marshal(str)

	req, err := http.NewRequest("POST", dmn, bytes.NewBuffer(jsn))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	rmp, err := MapAuth0Response(resp)
	if err != nil {
		return rmp, err
	}

	if resp.StatusCode == 200 {
		fmt.Println("       ...User signed in successfully")
		return rmp, nil
	}
	if resp.StatusCode == 400 {
		return nil, errors.New("Invalid Request")
	}
	return rmp, errors.New(fmt.Sprintf("Signin User: %v", resp.StatusCode))
}

//The UserPasswordless method for Auth0Client takes the username and a proto "code"/"link"
//for a user and returns a bool of whether the passwordless email was sent
func (ac *Auth0Client) UserPasswordless(Username string, proto string) (bool, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", ac.Domain.Scheme, ac.Domain.Host, ac.Domain.Path, "passwordless/start")

	str := Auth0Payload{ClientID: ac.ClientID, Email: Username, Connection: "email", Send: proto}

	jsn, err := json.Marshal(str)

	req, err := http.NewRequest("POST", dmn, bytes.NewBuffer(jsn))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("       ...User passwordless email sent successfully")
		return true, nil
	}
	if resp.StatusCode == 400 {
		return false, errors.New("Invalid Request")
	}
	return false, errors.New(fmt.Sprintf("Signin User: %v", resp.StatusCode))
}

//The UserPassChange method for Auth0Client takes the desired username and password
//of a user and returns a map string interface with the json response
func (ac *Auth0Client) UserPassChange(Username string) (bool, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", ac.Domain.Scheme, ac.Domain.Host, ac.Domain.Path, "dbconnections/change_password")

	str := Auth0Payload{ClientID: ac.ClientID, Domain: dmn, Email: Username, Connection: "Username-Password-Authentication"}

	jsn, err := json.Marshal(str)

	req, err := http.NewRequest("POST", dmn, bytes.NewBuffer(jsn))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("Password-Change email sent successfully")
		return true, nil
	}
	if resp.StatusCode == 400 {
		return false, errors.New("Invalid Request")
	}
	return false, errors.New(fmt.Sprintf("Change Password Email: %v", resp.StatusCode))
}

type UserToken struct {
	IdToken string `json:"id_token"`
}

//The UserProfile method for Auth0Client takes the user IdToken
//of a user and returns a map[string]interface with the json response
//DOes not work, CANT FIGURE OUT THE GET REQUEST PARAMETERS
func (ac *Auth0Client) UserProfileAT(IdToken interface{}) (UserProfile, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", ac.Domain.Scheme, ac.Domain.Host, ac.Domain.Path, "userinfo")

	req, err := http.NewRequest("GET", dmn, bytes.NewBuffer([]byte("")))
	req.Header.Set("Authorization", fmt.Sprintf("%s",IdToken))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	var up UserProfile

	if resp.StatusCode == 200 {
		fmt.Println("       ...User profile retreieved successfully")
		ur, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		err = json.Unmarshal(ur, &up)
		if err != nil {
			log.Fatal(err)
		}
		return up, nil
	}
	if resp.StatusCode == 400 {
		var rk UserProfile
		return rk, errors.New("Invalid Request")
	}
	return up, errors.New(fmt.Sprintf("Signin User: %v", resp.StatusCode))
}

//The UserProfile method for Auth0Client takes the user IdToken
//of a user and returns a map[string]interface with the json response
func (ac *Auth0Client) UserProfileJWT(IdToken interface{}) (UserProfile, error) {
	dmn := fmt.Sprintf("%s://%s/%s%s", ac.Domain.Scheme, ac.Domain.Host, ac.Domain.Path, "tokeninfo")

	var jsn UserToken
	bstr := []byte(fmt.Sprintf(`{"id_token":"%s"}`, IdToken))

	err := json.Unmarshal(bstr, &jsn)
	if err != nil {
		log.Fatal(err)
	}

	s, err := json.Marshal(jsn)

	req, err := http.NewRequest("POST", dmn, bytes.NewBuffer([]byte(s)))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	var up UserProfile

	if resp.StatusCode == 200 {
		fmt.Println("       ...User profile retreieved successfully")
		ur, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		err = json.Unmarshal(ur, &up)
		if err != nil {
			log.Fatal(err)
		}
		return up, nil
	}
	if resp.StatusCode == 400 {
		var rk UserProfile
		return rk, errors.New("Invalid Request")
	}
	return up, errors.New(fmt.Sprintf("Signin User: %v", resp.StatusCode))
}

//Function MapAuth0Response takes parameters of type http.Response
func MapAuth0Response(r *http.Response) (rmp map[string]interface{}, err error) {
	bresp, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return rmp, errors.New("Error reading response body with ioutil")
	}
	err = json.Unmarshal(bresp, &rmp)
	if err != nil {
		return rmp, errors.New("Error unmarshaling reponse into JSON")
	}
	if r.StatusCode == 200 {
		fmt.Println("Successful Request:\n")
		for i, a := range rmp {
			fmt.Println(fmt.Sprint(i, ": ", a))
		}
	} else {
		//Run a switch{ case: } for each status code, maybe helper function for all none 200 level status codes
		fmt.Println("Failed Request:\n", rmp["statusCode"], rmp["name"], rmp["description"])
	}
	return rmp, nil
}
