package main

import (
	_ "github.com/captncraig/caddy-oauth"
	"github.com/caddyserver/caddy/caddy/caddymain"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func main() {
	httpserver.RegisterDevDirective("oauth", "jwt")
	caddymain.Run()
}
