package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"testing"

	"github.com/PastureStack/host-api/config"
	jwt "github.com/golang-jwt/jwt/v5"
)

func TestAuthStoresTokenOnlyAfterHostBindingSucceeds(t *testing.T) {
	original := config.Config
	t.Cleanup(func() { config.Config = original })

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"hostUuid": "other-host",
	}).SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	config.Config.Auth = true
	config.Config.HostUuidCheck = true
	config.Config.HostUuid = "expected-host"
	config.Config.ParsedPublicKey = &privateKey.PublicKey

	request := httptest.NewRequest("GET", "https://host.test/v1/stats?token="+signed, nil)
	response := httptest.NewRecorder()
	if Auth(response, request) {
		t.Fatal("token for another host was accepted")
	}
	if GetToken(request) != nil {
		t.Fatal("rejected token was retained in the request context")
	}
}
