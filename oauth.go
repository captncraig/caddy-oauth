package oauth

import (
	"context"
	"crypto/rand"
	"net/http"

	"encoding/base64"

	"fmt"

	"github.com/captncraig/caddy-oauth/providers"
	"golang.org/x/oauth2"
)

func (o *oathPlugin) stripHeaders(r *http.Request) {
	for _, p := range o.providers {
		for _, h := range p.HeadersUsed() {
			r.Header.Del(h)
		}
	}
}

func (o *oathPlugin) loginPage(w http.ResponseWriter, r *http.Request) (int, error) {
	return 0, nil
}

func (o *oathPlugin) logout(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, p := range o.providerConfigs {
		o.cookies.ClearCookie(w, p.CookieName)
	}
	//TODO: customizable?
	http.Redirect(w, r, "/", http.StatusFound)
	return http.StatusFound, nil
}

func (o *oathPlugin) start(w http.ResponseWriter, r *http.Request, p providers.Provider) (int, error) {
	dat := make([]byte, 9)
	rand.Read(dat)
	state := base64.StdEncoding.EncodeToString(dat)
	o.cookies.SetCookie(w, "oauth-state", 120, state)
	url := p.OauthConfig().AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusFound)
	return http.StatusFound, nil
}

func (o *oathPlugin) callback(w http.ResponseWriter, r *http.Request, p providers.Provider, cfg *providers.ProviderConfig) (int, error) {
	fail := func(e error) (int, error) {
		fmt.Println("FIAIL", e)
		return 200, nil
	}
	var err error
	code, state := r.URL.Query().Get("code"), r.URL.Query().Get("state")
	var foundState string
	if err = o.cookies.ReadCookie(r, "oauth-state", 120, &foundState); err != nil {
		return fail(err)
	}
	o.cookies.ClearCookie(w, "oauth-state")
	if foundState != state {
		return fail(fmt.Errorf("state does not match"))
	}
	var tok *oauth2.Token
	if tok, err = p.OauthConfig().Exchange(context.Background(), code); err != nil {
		return fail(err)
	}

	headers, err := p.GetUserData(tok)
	if err != nil {
		return fail(err)
	}
	if err = o.cookies.SetCookie(w, cfg.CookieName, cookieDuration, headers); err != nil {
		return fail(err)
	}
	return o.successRedirect(w, r)
}

var cookieDuration = 60 * 60 * 24 * 30

func (o *oathPlugin) successRedirect(w http.ResponseWriter, r *http.Request) (int, error) {
	//TODO: read cookie and redirect to that url.
	// Otherwise / (or maybe a configurable path)
	http.Redirect(w, r, "/", http.StatusFound)
	return http.StatusFound, nil
}
