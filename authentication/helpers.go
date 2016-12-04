package authentication

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

//Function MapAuth0Response takes parameters of type http.Response
func MapAuth0Response(r *http.Response) (rmp map[string]interface{}, err error) {
	bresp, err := ioutil.ReadAll(r.Body) //Read response body
	if err != nil {
		return rmp, errors.New("Error reading response body with ioutil")
	}
	err = json.Unmarshal(bresp, &rmp) //Unmarshal response into map[string]interface{}
	if err != nil {
		return rmp, errors.New("Error unmarshaling reponse into JSON")
	}

	switch {
	case r.StatusCode == 200:
		fmt.Println("Request Completed Successfully")
		return rmp, nil
	case r.StatusCode > 400 && r.StatusCode < 500:
		fmt.Println("Failed Request:\n", rmp["statusCode"], rmp["name"], rmp["description"])
		return nil, errors.New(fmt.Sprintf("Invalid Request: %d", r.StatusCode))
	}

	return nil, errors.New(fmt.Sprintf("Mapping the Auth0 Response Failed:\n", fmt.Sprintf("%+v\n", r.Body)))
}
