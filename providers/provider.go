package providers

import (
	"golang.org/x/oauth2"
)

// A provider can wrap an error in VisibleError to make it visible to the end user.
// Otherwise they will get a generic "auth failure" message.
type VisibleError struct {
	error
}

type Provider interface {
	OauthConfig() *oauth2.Config
	HeadersUsed() []string
	GetUserData(*oauth2.Token) (map[string]string, error)
}

type ProviderConfig struct {
	Provider
	//For provider specific config data, we pass you the key/value pairs directly.
	//Each time a key is seen, a new array will be added with all args, so multiple args on multiple lines are distinguishable.
	Params map[string][][]string

	//name for this provider's cookie. default: auth-$provider
	CookieName string
	//route that redirects to login. default: /auth/$provider/start
	StartRoute string
	//route for callback. Must be unique. default: /auth/$provider/callback
	CallbackRoute string

	//required oauth params
	ClientSecret  string
	ClientID      string
	Scopes        []string
}
