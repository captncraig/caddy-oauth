package github

import (
	"context"

	"fmt"
	"net/http"

	"encoding/json"

	"github.com/captncraig/caddy-oauth/providers"
	"golang.org/x/oauth2"
	ghoauth "golang.org/x/oauth2/github"
)

type githubProvider struct {
	*providers.ProviderConfig

	restrict     bool
	allowedUsers []string
	allowedOrgs  []string
	allowedRepos [][]string
}

func New(p *providers.ProviderConfig) (providers.Provider, error) {
	g := &githubProvider{ProviderConfig: p}
	for k, vs := range p.Params {
		switch k {
		case "allowed_users":
			for _, v := range vs {
				for _, u := range v {
					g.allowedUsers = append(g.allowedUsers, u)
				}
			}
		case "allowed_orgs":
			for _, v := range vs {
				for _, o := range v {
					g.allowedOrgs = append(g.allowedOrgs, o)
				}
			}
		case "allow_repo_members":
			for _, v := range vs {
				if len(v) != 2 {
					return nil, fmt.Errorf("github_allow_repo_members expects 2 arguments for owner and repo name")
				}
				g.allowedRepos = append(g.allowedRepos, []string{v[0], v[1]})
			}
		default:
			return nil, fmt.Errorf("unkown github config item github_%s", k)
		}
	}
	if g.allowedOrgs != nil || g.allowedRepos != nil || g.allowedUsers != nil {
		g.restrict = true
	}
	return g, nil
}

const (
	idHeader     = "X-Github-ID"
	userHeader   = "X-Github-User"
	tokenHeader  = "X-Github-Token"
	avatarHeader = "X-Github-Avatar"
)

var headers = []string{
	idHeader,
	userHeader,
	tokenHeader,
	avatarHeader,
}

func (g *githubProvider) OauthConfig() *oauth2.Config {
	return &oauth2.Config{
		Endpoint:     ghoauth.Endpoint,
		ClientID:     g.ClientID,
		ClientSecret: g.ClientSecret,
		Scopes:       g.Scopes,
	}
}

func (g *githubProvider) HeadersUsed() []string {
	return headers
}

type ghUser struct {
	ID     int    `json:"id"`
	Login  string `json:"login"`
	Avatar string `json:"avatar_url"`
}

const apiBase = "https://api.github.com"

func (g *githubProvider) GetUserData(tok *oauth2.Token) (map[string]string, error) {
	c := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(tok))
	resp, err := c.Get(apiBase + "/user")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Status from github: %d", resp.StatusCode)
	}
	dec := json.NewDecoder(resp.Body)
	user := &ghUser{}
	if err = dec.Decode(user); err != nil {
		return nil, err
	}
	data := map[string]string{
		idHeader:     fmt.Sprint(user.ID),
		avatarHeader: user.Avatar,
		userHeader:   user.Login,
		tokenHeader:  tok.AccessToken,
	}
	if !g.restrict {
		return data, nil
	}
	for _, u := range g.allowedUsers {
		if u == user.Login {
			return data, nil
		}
	}
	for _, o := range g.allowedOrgs {
		if g.userMemberOfOrg(c, user.Login, o) {
			return data, nil
		}
	}
	for _, r := range g.allowedRepos {
		if g.userMemberOfRepo(c, user.Login, r) {
			return data, nil
		}
	}
	return nil, fmt.Errorf("User not authorized")
}

func (g *githubProvider) userMemberOfOrg(c *http.Client, u string, org string) bool {
	url := fmt.Sprintf("%s/orgs/%s/members/%s", apiBase, org, u)
	resp, err := c.Get(url)
	if err == nil && resp.StatusCode == http.StatusNoContent {
		return true
	}
	return false
}

func (g *githubProvider) userMemberOfRepo(c *http.Client, u string, repo []string) bool {
	url := fmt.Sprintf("%s/repos/%s/%s/collaborators/%s", apiBase, repo[0], repo[1], u)
	resp, err := c.Get(url)
	if err == nil && resp.StatusCode == http.StatusNoContent {
		return true
	}
	return false
}
