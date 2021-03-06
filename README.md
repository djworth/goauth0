# go-auth0
To be a full-coverage package for Auth0 Authentication and Management APIs

![alt text](assets/GoAuth0-Gopher.png)

## API Coverage:

  - [ ] Authentication:
    * [x] Login
    * [x] Logout
    * [x] Passwordless
    * [x] Signup User
    * [x] Change Password
    * [x] User Profile
    * [ ] SAML
    * [ ] WS-Federation
    * [ ] Impersonation
    * [ ] Account Linking
    * [ ] Impersonation
    * [ ] Delegation
    * [ ] API Authorization

  - [ ] Management:
    * [ ] Client Grants
    * [ ] Clients
    * [ ] Connections
    * [ ] Device Credentials
    * [ ] Grants
    * [ ] Logs
    * [ ] Resource Servers
    * [ ] Rules
    * [ ] User Blocks
    * [ ] Users
    * [ ] Blacklists
    * [ ] Emails
    * [ ] Guardian
    * [ ] Jobs
    * [ ] Stats
    * [ ] Tenants
    * [ ] Tickets

  - [ ] Error Codes

## Usage

> Create a Auth0 authentication Client by passing the ClientID and Domain for your app
```
client, err := goauth0.NewAuth0Client(os.Getenv("AUTH0_CLIENT_ID"), os.Getenv("AUTH0_DOMAIN"))
if err != nil {
  log.Fatal(err)
}
```

> Obtaining user authentication tokens can be completed through functions located in the login file.
```
userTokens, err := client.UserPasswordSignin("schmorrison@gmail.com", "Test1234")
if err != nil {
  log.Fatal(err)
}
```

> Obtaining user information can be retrieved from auth0 by either passing the JWT or the accesstoken, obtained from the signin function, to the corresponding auth0Client.UserProfile[JWT|AT] function. The fields of the userprofile type is closely matched to the auth0 json representation
```
userProfile, err := client.UserProfileJWT(a["id_token"])
if err != nil {
  log.Fatal(err)
}
```
