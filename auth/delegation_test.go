package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/delegation"
	"github.com/PastureStack/host-api/testutils"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestScopedHostHandshakeRequiresEngineAndExactHostOperation(t *testing.T) {
	prior := config.Config
	defer func() { config.Config = prior }()
	var deny atomic.Bool
	expiry := time.Now().Add(time.Hour).Unix()
	payload := map[string]interface{}{delegation.Claim: map[string]interface{}{"version": 1, "keyId": 12, "revision": 3, "targetType": "container", "targetId": "1i9", "operation": "exec", "expiresAt": expiry,
		"payload": map[string]interface{}{"hostUuid": "h1", "exec": map[string]interface{}{"Container": "docker9"}}}, "exp": expiry}
	raw := testutils.CreateTokenWithPayload(payload, testutils.ParseTestPrivateKey())
	digest := sha256.Sum256([]byte(raw))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if deny.Load() {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"allowed": true, "keyId": 12, "revision": 3, "targetType": "container", "targetId": "1i9", "operation": "exec", "expiresAt": expiry, "tokenDigest": hex.EncodeToString(digest[:])})
	}))
	defer server.Close()
	config.Config.ParsedPublicKey = testutils.ParseTestPublicKey()
	config.Config.HostUuid = "h1"
	config.Config.HostUuidCheck = true
	config.Config.PlatformURL = server.URL
	token, valid := GetAndCheckStreamToken(raw, "/v2-beta/exec/")
	if !valid {
		t.Fatal("valid scoped exec denied")
	}
	if _, found := GetClaimMap(token, "exec"); !found {
		t.Fatal("verified envelope not exposed to exec handler")
	}
	if _, valid := GetAndCheckStreamToken(raw, "/v2-beta/logs/"); valid {
		t.Fatal("exec ticket became logs authority")
	}
	if _, valid := GetAndCheckToken(raw); valid {
		t.Fatal("scoped token entered an unbound sink")
	}
	config.Config.HostUuid = "h2"
	if _, valid := GetAndCheckStreamToken(raw, "/v2-beta/exec/"); valid {
		t.Fatal("other host accepted")
	}
	config.Config.HostUuid = "h1"
	deny.Store(true)
	if _, valid := GetAndCheckStreamToken(raw, "/v2-beta/exec/"); valid {
		t.Fatal("revoked Engine permission accepted")
	}
	legacy := testutils.CreateToken("h1", testutils.ParseTestPrivateKey())
	config.Config.PlatformURL = ""
	if _, valid := GetAndCheckToken(legacy); !valid {
		t.Fatal("legacy requires new Engine")
	}
}
