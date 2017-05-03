package main

import (
	_ "github.com/captncraig/caddy-oauth"
	"github.com/mholt/caddy/caddy/caddymain"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func main() {
	httpserver.RegisterDevDirective("oauth", "jwt")
	caddymain.Run()
}
