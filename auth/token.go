package auth

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	expectedJWTAlg = "RS256"
	maxJWTBytes    = 16 << 10
	minRSAKeyBits  = 2048
)

func ParseToken(tokenString string, parsedPublicKey interface{}) (*jwt.Token, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("no JWT token provided")
	}
	if len(tokenString) > maxJWTBytes {
		return nil, fmt.Errorf("JWT token exceeds %d bytes", maxJWTBytes)
	}
	publicKey, ok := parsedPublicKey.(*rsa.PublicKey)
	if !ok || publicKey == nil || publicKey.N == nil || publicKey.N.BitLen() < minRSAKeyBits {
		return nil, fmt.Errorf("JWT verification requires an RSA public key of at least %d bits", minRSAKeyBits)
	}

	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		method, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok || method.Alg() != expectedJWTAlg {
			return nil, fmt.Errorf("unexpected JWT signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	}, jwt.WithValidMethods([]string{expectedJWTAlg}), jwt.WithJSONNumber())
}

func GetClaim(token *jwt.Token, key string) (interface{}, bool) {
	claims, ok := MapClaims(token)
	if !ok {
		return nil, false
	}
	value, found := claims[key]
	return value, found
}

func GetClaimString(token *jwt.Token, key string) (string, bool) {
	value, found := GetClaim(token, key)
	if !found {
		return "", false
	}
	valueString, ok := value.(string)
	return valueString, ok
}

func HasScope(token *jwt.Token, expected string) bool {
	if expected == "" {
		return false
	}
	scope, found := GetClaimString(token, "scope")
	return found && scope == expected
}

func GetClaimMap(token *jwt.Token, key string) (map[string]interface{}, bool) {
	value, found := GetClaim(token, key)
	if !found {
		return nil, false
	}
	valueMap, ok := value.(map[string]interface{})
	return valueMap, ok
}

func MapClaims(token *jwt.Token) (jwt.MapClaims, bool) {
	if token == nil {
		return nil, false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	return claims, ok
}

func GetMapString(values map[string]interface{}, key string) (string, bool) {
	value, found := values[key]
	if !found {
		return "", false
	}
	result, ok := value.(string)
	return result, ok
}

func GetMapBool(values map[string]interface{}, key string) (bool, bool) {
	value, found := values[key]
	if !found {
		return false, false
	}
	result, ok := value.(bool)
	return result, ok
}

func GetMapInt64(values map[string]interface{}, key string) (int64, bool) {
	value, found := values[key]
	if !found {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed || typed < math.MinInt64 || typed > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case json.Number:
		result, err := typed.Int64()
		return result, err == nil
	default:
		return 0, false
	}
}
