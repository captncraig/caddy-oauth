package oauth

import (
	"fmt"
	"net/http"

	"strings"

	"github.com/captncraig/caddy-oauth/providers"
	"github.com/captncraig/caddy-oauth/providers/github"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type oathPlugin struct {
	next httpserver.Handler

	//route for a generated landing page with a login button for each provider. default: /login
	loginRoute string
	//route to delete all cookies. default: /logout
	logoutRoute string
	//should we add headers for downstream requests to see or not? headers are provider specific. default: false
	passHeaders bool
	//routes that require login from at least one provider. default: none
	protectedRoutes []string

	// internal things
	cookies         *cookieManager
	providerConfigs map[string]*providers.ProviderConfig
	providers       map[string]providers.Provider
}

type providerInit func(*providers.ProviderConfig) (providers.Provider, error)

var providerTypes = map[string]providerInit{
	"github": github.New,
}

func init() {
	plug := caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	}
	caddy.RegisterPlugin("oauth", plug)
}

func setup(c *caddy.Controller) (err error) {
	var o *oathPlugin
	for c.Next() {
		if o != nil {
			return c.Err("Cannot define oauth more than once per server")
		}
		o = &oathPlugin{
			loginRoute:      "/login",
			logoutRoute:     "/logout",
			passHeaders:     false,
			providerConfigs: map[string]*providers.ProviderConfig{},
			providers:       map[string]providers.Provider{},
		}
		o.protectedRoutes = c.RemainingArgs()
		for c.NextBlock() {
			if err := parseArg(c, o); err != nil {
				return err
			}
		}
	}
	if o.cookies == nil {
		if o.cookies, err = getCookie(""); err != nil {
			return err
		}
	}
	if len(o.providerConfigs) == 0 {
		return c.Errf("At least one oauth provider must be specified")
	}
	for name, cfg := range o.providerConfigs {
		if cfg.ClientID == "" || cfg.ClientSecret == "" {
			return c.Errf("need %s_client_id and %s_client_secret", name, name)
		}
		prov, err := providerTypes[name](cfg)
		if err != nil {
			return err
		}
		o.providers[name] = prov
	}

	cfg := httpserver.GetConfig(c)
	mid := func(next httpserver.Handler) httpserver.Handler {
		o.next = next
		return o
	}
	cfg.AddMiddleware(mid)
	return nil
}

func parseArg(c *caddy.Controller, o *oathPlugin) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
			}
		}
	}()
	v := c.Val()
	switch v {
	case "login":
		o.loginRoute = singleArg(c)
	case "logout":
		o.logoutRoute = singleArg(c)
	case "pass_headers":
		if len(c.RemainingArgs()) != 0 {
			return c.ArgErr()
		}
		o.passHeaders = true
	case "cookie_secret":
		if o.cookies, err = getCookie(singleArg(c)); err != nil {
			return err
		}
	default:
		//either provider specific config, or an unknown key
		parts := strings.SplitN(c.Val(), "_", 2)
		if len(parts) != 2 {
			return c.Errf("Unkown oauth config item %s", v)
		}
		pname := parts[0]
		_, ok := providerTypes[pname]
		if !ok {
			return c.Errf("Unkown oauth provider type %s", parts[0])
		}
		var pcfg = o.providerConfigs[pname]
		if pcfg == nil {
			pcfg = &providers.ProviderConfig{
				CallbackRoute: fmt.Sprintf("/auth/%s/callback", pname),
				StartRoute:    fmt.Sprintf("/auth/%s/start", pname),
				CookieName:    fmt.Sprintf("auth-%s", pname),
				Params:        map[string][][]string{},
			}
			o.providerConfigs[parts[0]] = pcfg
		}
		switch parts[1] {
		case "callback":
			pcfg.CallbackRoute = singleArg(c)
		case "start":
			pcfg.StartRoute = singleArg(c)
		case "cookie_name":
			pcfg.CookieName = singleArg(c)
		case "client_secret":
			pcfg.ClientSecret = singleArg(c)
		case "client_id":
			pcfg.ClientID = singleArg(c)
		case "scopes":
			pcfg.Scopes = append(pcfg.Scopes, c.RemainingArgs()...)
		default:
			pcfg.Params[parts[1]] = append(pcfg.Params[parts[1]], c.RemainingArgs())
		}
	}
	return nil
}

func singleArg(c *caddy.Controller) string {
	if args := c.RemainingArgs(); len(args) == 1 {
		return args[0]
	}
	panic(c.ArgErr())
}

func (o *oathPlugin) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	path := httpserver.Path(r.URL.Path)
	// 1. special routes we handle ourselves
	if path.Matches(o.loginRoute) {
		return o.loginPage(w, r)
	}
	if path.Matches(o.logoutRoute) {
		return o.logout(w, r)
	}
	for name, p := range o.providerConfigs {
		if path.Matches(p.StartRoute) {
			return o.start(w, r, o.providers[name])
		}
		if path.Matches(p.CallbackRoute) {
			return o.callback(w, r, o.providers[name], p)
		}
	}
	any := false
	// 2. check all cookies, populate downstream headers
	for _, p := range o.providerConfigs {
		dat := map[string]string{}
		if err := o.cookies.ReadCookie(r, p.CookieName, cookieDuration, &dat); err == nil {
			for k, v := range dat {
				r.Header.Set(k, v)
			}
			any = true
		}
	}
	if !any {
		fmt.Println("DENY!")
	}
	// 3. deny if configured
	return o.next.ServeHTTP(w, r)
}

//TODO: possible actions on DENY:
//1. Redirect to $loginRoute, storing desired path in cookie (CURRENT)
//2. Redirect to route of user's choice.
//3. Straight up 403 (CURRENT if request does not accept html)
//4. REWRITE to some other path
