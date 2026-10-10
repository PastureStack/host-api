package auth

import (
	"context"
	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/delegation"
	jwt "github.com/golang-jwt/jwt/v5"
)

func verifyDelegation(raw, path string, token *jwt.Token) (*jwt.Token, bool) {
	claims, ok := MapClaims(token)
	if !ok {
		return token, false
	}
	grant, err := delegation.Parse(map[string]interface{}(claims))
	if err != nil {
		return token, false
	}
	if grant == nil {
		return token, true
	}
	verifier := delegation.New(config.Config.PlatformURL)
	if path == "" || !grant.AllowsPath(path) || verifier.Check(context.Background(), raw, grant) != nil {
		return token, false
	}
	normalized := jwt.MapClaims{}
	for key, value := range claims {
		normalized[key] = value
	}
	for key, value := range grant.Payload {
		normalized[key] = value
	}
	copyToken := *token
	copyToken.Claims = normalized
	return &copyToken, true
}

// The original signed token, not normalized claims, is rechecked for every tick.
func StartStreamWatch(parent context.Context, raw string, verified *jwt.Token, deny func()) context.CancelFunc {
	initial, ok := MapClaims(verified)
	if ok {
		if _, scoped := initial[delegation.Claim]; !scoped {
			return func() {}
		}
	}
	token, err := ParseToken(raw, config.Config.ParsedPublicKey)
	if err != nil {
		deny()
		return func() {}
	}
	claims, ok := MapClaims(token)
	if !ok {
		deny()
		return func() {}
	}
	grant, err := delegation.Parse(map[string]interface{}(claims))
	if err != nil {
		deny()
		return func() {}
	}
	return delegation.New(config.Config.PlatformURL).Watch(parent, raw, grant, deny)
}
