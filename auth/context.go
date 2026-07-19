package auth

import (
	"context"
	"net/http"

	jwt "github.com/golang-jwt/jwt/v5"
)

type key int

const TokenKey key = 0

func GetToken(r *http.Request) *jwt.Token {
	if token, ok := r.Context().Value(TokenKey).(*jwt.Token); ok {
		return token
	}
	return nil
}

func SetToken(r *http.Request, val *jwt.Token) {
	*r = *r.WithContext(context.WithValue(r.Context(), TokenKey, val))
}
