package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestParseTokenRejectsOversizedTokenAndWeakKey(t *testing.T) {
	if _, err := ParseToken(strings.Repeat("a", maxJWTBytes+1), nil); err == nil {
		t.Fatal("oversized JWT was accepted")
	}
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"hostUuid": "host-1"})
	signed, err := token.SignedString(weakKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseToken(signed, &weakKey.PublicKey); err == nil {
		t.Fatal("JWT signed with a weak RSA key was accepted")
	}
}

func TestMapClaimConversionsAreSafe(t *testing.T) {
	values := map[string]interface{}{
		"string": "value",
		"bool":   true,
		"float":  float64(42),
		"number": json.Number("43"),
		"bad":    1.5,
	}
	if value, ok := GetMapString(values, "string"); !ok || value != "value" {
		t.Fatalf("unexpected string claim: %q, %v", value, ok)
	}
	if value, ok := GetMapBool(values, "bool"); !ok || !value {
		t.Fatalf("unexpected boolean claim: %v, %v", value, ok)
	}
	if value, ok := GetMapInt64(values, "float"); !ok || value != 42 {
		t.Fatalf("unexpected float claim: %d, %v", value, ok)
	}
	if value, ok := GetMapInt64(values, "number"); !ok || value != 43 {
		t.Fatalf("unexpected number claim: %d, %v", value, ok)
	}
	if _, ok := GetMapInt64(values, "bad"); ok {
		t.Fatal("fractional claim was accepted as an integer")
	}
}

func TestHasScopeRequiresExactStringClaim(t *testing.T) {
	valid := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"scope": "dockersocket"})
	if !HasScope(valid, "dockersocket") {
		t.Fatal("exact scope was rejected")
	}
	for _, claims := range []jwt.MapClaims{
		{},
		{"scope": "logs"},
		{"scope": []string{"dockersocket"}},
	} {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		if HasScope(token, "dockersocket") {
			t.Fatalf("invalid scope was accepted: %#v", claims)
		}
	}
	if HasScope(valid, "") {
		t.Fatal("empty expected scope was accepted")
	}
}
