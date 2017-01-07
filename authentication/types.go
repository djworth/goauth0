package authentication

import (
	"net/url"
)

type Auth0Client struct {
	ClientID string
	Domain   *url.URL
}

type Auth0Payload struct {
	ClientID    string `json:"client_id,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone_number,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
	Connection  string `json:"connection,omitempty"`
	GrantType   string `json:"grant_type,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Send        string `json:"send,omitempty"`
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
	Identities        []Identity
	CreatedAt         string `json:"created_at"`
	LastPasswordReset string `json:"last_password_reset"`
	GlobalClientId    string `json:"global_client_id"`
}

type UserToken struct {
	IdToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type Identity struct {
	UserId     string `json:"user_id"`
	Provider   string `json:"provider"`
	Connection string `json:"connection"`
	IsSocial   bool   `json:"isSocial"`
}
