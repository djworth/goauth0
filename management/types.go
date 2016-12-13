package management

import (
	"net/url"

	jwt "github.com/dgrijalva/jwt-go"
)

type Auth0Client struct {
	ClientID     string
	ClientSecret string
	Domain       *url.URL
	Token        *jwt.Token
}

type NewTokenPayload struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type Users []UserPayload

type UserPayload struct {
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Username      string                 `json:"username"`
	Phone         string                 `json:"phone_number"`
	PhoneVerified bool                   `json:"phone_verified"`
	UserId        string                 `json:"user_id"`
	CreatedAt     string                 `json:"created_at"`
	UpdatedAt     string                 `json:"updated_at"`
	Identities    []Identity             `json:"identities"`
	AppMetadata   map[string]interface{} `json:"app_metadata"`
	UserMetadata  map[string]interface{} `json:"user_metadata"`
	Picture       string                 `json:"picture"`
	Name          string                 `json:"name"`
	Nickname      string                 `json:"nickname"`
	Multifactor   []string               `json:"multifactor"`
	LastIp        string                 `json:"last_ip"`
	LastLogin     string                 `json:"last_login"`
	LoginsCount   int                    `json:"logins_count"`
	Blocked       bool                   `json:"blocked"`
	GivenName     string                 `json:"given_name"`
	FamilyName    string                 `json:"family_name"`
}

type Identity struct {
	UserId     string `json:"user_id"`
	Provider   string `json:"provider"`
	Connection string `json:"connection"`
	IsSocial   bool   `json:"isSocial"`
}
