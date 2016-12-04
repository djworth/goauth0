# goauth0
Simple wrapper functions for auth0 authentication api

###Usage


Create a Auth0 authentication Client by passing the ClientID and Domain for your app
```
client, err := goauth0.NewAuth0Client(os.Getenv("AUTH0_CLIENT_ID"), os.Getenv("AUTH0_DOMAIN"))
if err != nil {
  log.Fatal(err)
}
```

Obtaining user authentication tokens can be completed through functions located in
the login file.
```
userTokens, err := client.UserPasswordSignin("schmorrison@gmail.com", "Test1234")
if err != nil {
  log.Fatal(err)
}
```

Obtaining user information can be retrieved from auth0 by either passing the JWT or the accesstoken,
obtained from the signin function, to the corresponding auth0Client.UserProfile[JWT|AT] function.
The fields of the userprofile type is closely matched to the auth0 json representation
```
userProfile, err := client.UserProfileJWT(a["id_token"])
if err != nil {
  log.Fatal(err)
}
```