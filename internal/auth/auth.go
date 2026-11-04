package auth

import (
	"net/http"
	"strings"
)

type Principal struct {
	Name       string
	Authorized bool
}

type Authenticator interface {
	Authenticate(*http.Request) Principal
}

type TokenAuthenticator struct {
	tokens map[string]string
}

func ParseCredentials(value string) map[string]string {
	credentials := make(map[string]string)
	for _, item := range strings.Split(value, ",") {
		name, token, ok := strings.Cut(strings.TrimSpace(item), "=")
		if ok && strings.TrimSpace(name) != "" && strings.TrimSpace(token) != "" {
			credentials[strings.TrimSpace(name)] = strings.TrimSpace(token)
		}
	}
	return credentials
}

func NewTokenAuthenticator(tokens map[string]string) Authenticator {
	return &TokenAuthenticator{tokens: tokens}
}

func (a *TokenAuthenticator) Authenticate(r *http.Request) Principal {
	if len(a.tokens) == 0 {
		return Principal{Name: "anonymous", Authorized: true}
	}
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	for name, expected := range a.tokens {
		if token == expected {
			return Principal{Name: name, Authorized: true}
		}
	}
	return Principal{Name: "anonymous", Authorized: false}
}
