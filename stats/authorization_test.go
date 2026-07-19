package stats

import (
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestLegacyStatsAuthorizationBindsRequestedResource(t *testing.T) {
	hostToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"resourceId": "1h1",
	})
	if _, resourceID, ok := legacyStatsAuthorization(hostToken, ""); !ok || resourceID != "1h1" {
		t.Fatalf("valid host statistics claim was rejected: %q, %v", resourceID, ok)
	}
	if _, _, ok := legacyStatsAuthorization(hostToken, "container-1"); ok {
		t.Fatal("host statistics token authorized a container")
	}

	containerToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"containerIds": map[string]interface{}{"container-1": "1i1"},
	})
	containerIDs, _, ok := legacyStatsAuthorization(containerToken, "container-1")
	if !ok || containerIDs["container-1"] != "1i1" {
		t.Fatalf("valid container statistics claim was rejected: %#v, %v", containerIDs, ok)
	}
	if _, _, ok := legacyStatsAuthorization(containerToken, "container-2"); ok {
		t.Fatal("container statistics token authorized a different container")
	}
}

func TestStatsClaimsFailClosed(t *testing.T) {
	for _, claims := range []jwt.MapClaims{
		{},
		{"resourceId": ""},
		{"resourceId": strings.Repeat("x", maxStatsResourceIDBytes+1)},
		{"containerIds": map[string]interface{}{"container-1": 1}},
		{"containerIds": map[string]interface{}{"": "1i1"}},
	} {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		if _, _, ok := legacyStatsAuthorization(token, ""); ok {
			t.Fatalf("invalid host claim was accepted: %#v", claims)
		}
		if _, _, ok := legacyStatsAuthorization(token, "container-1"); ok {
			t.Fatalf("invalid container claim was accepted: %#v", claims)
		}
	}
}
