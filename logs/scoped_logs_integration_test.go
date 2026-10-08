package logs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/delegation"
	"github.com/PastureStack/host-api/events"
	"github.com/PastureStack/host-api/testutils"
	"github.com/PastureStack/websocket-proxy/common"
	docker "github.com/fsouza/go-dockerclient"
	jwt "github.com/golang-jwt/jwt/v5"
)

func TestScopedLogsActualDockerTerminalResults(t *testing.T) {
	if os.Getenv("PASTURESTACK_QA_LOG_FIXTURE") != "1" {
		t.Skip("requires explicitly enabled isolated Linux Docker fixture")
	}
	prior := config.Config
	defer func() { config.Config = prior }()
	config.Config.HostUuid = "wp4-fixture-host"
	config.Config.HostUuidCheck = true
	config.Config.ParsedPublicKey = testutils.ParseTestPublicKey()
	config.Config.PlatformAccessKey = "fixture-agent"
	config.Config.PlatformSecretKey = "fixture-agent-secret"
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	config.Config.CompletionSpoolDir = filepath.Join(parent, "completion-spool")
	client, err := events.NewDockerClient()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"EOF", "disconnect", "revoked", "handshake-denied"} {
		t.Run(mode, func(t *testing.T) {
			container, err := client.CreateContainer(docker.CreateContainerOptions{Name: "pasturestack-wp4-logs-" + mode,
				Config: &docker.Config{Image: "pasturestack/host-api-log-fixture:latest", Labels: map[string]string{"pasturestack.qa.fixture": "api-key-wp4-20261008"}}})
			if err != nil {
				t.Fatal(err)
			}
			defer client.RemoveContainer(docker.RemoveContainerOptions{ID: container.ID, Force: true})
			if err := client.StartContainer(container.ID, nil); err != nil {
				t.Fatal(err)
			}
			expires := time.Now().Add(3 * time.Minute).Unix()
			claims := map[string]interface{}{delegation.Claim: map[string]interface{}{"version": 1, "issuedAt": time.Now().Unix(), "keyId": 12, "revision": 3, "targetType": "container", "targetId": "1i9", "operation": "logs", "expiresAt": expires,
				"payload": map[string]interface{}{"hostUuid": "wp4-fixture-host", "logs": map[string]interface{}{"Container": container.ID, "Follow": mode != "EOF"}}}, "exp": expires}
			raw := testutils.CreateTokenWithPayload(claims, testutils.ParseTestPrivateKey())
			digest := sha256.Sum256([]byte(raw))
			terminal := make(chan map[string]string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2-beta/apiKeyDelegationCompletion" {
					user, password, ok := r.BasicAuth()
					if !ok || user != "fixture-agent" || password != "fixture-agent-secret" {
						t.Error("terminal event lacks agent authentication")
					}
					var body map[string]string
					json.NewDecoder(r.Body).Decode(&body)
					terminal <- body
					json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
					return
				}
				if mode == "handshake-denied" {
					w.WriteHeader(403)
					return
				}
				json.NewEncoder(w).Encode(map[string]interface{}{"allowed": true, "keyId": 12, "revision": 3, "targetType": "container", "targetId": "1i9", "operation": "logs", "expiresAt": expires, "tokenDigest": hex.EncodeToString(digest[:])})
			}))
			defer server.Close()
			config.Config.PlatformURL = server.URL
			incoming := make(chan string)
			defer func() {
				if mode != "disconnect" {
					close(incoming)
				}
			}()
			response := make(chan common.Message, 128)
			watcher := make(chan func(), 1)
			handler := &LogsHandler{streamWatch: func(_ context.Context, _ string, _ *jwt.Token, denied func()) context.CancelFunc {
				watcher <- denied
				return func() {}
			}}
			done := make(chan struct{})
			go func() { handler.Handle("fixture", "/v2-beta/logs/?token="+raw, incoming, response); close(done) }()
			if mode == "disconnect" || mode == "revoked" {
				var deny func()
				select {
				case deny = <-watcher:
				case <-time.After(10 * time.Second):
					t.Fatal("handshake did not reach live watcher")
				}
				select {
				case message := <-response:
					if message.Type != common.Body {
						t.Fatal("stream closed before Docker output")
					}
				case <-time.After(10 * time.Second):
					t.Fatal("Docker output barrier not reached")
				}
				if mode == "revoked" {
					deny()
				} else {
					close(incoming)
				}
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("stream did not terminate")
			}
			var event map[string]string
			select {
			case event = <-terminal:
			case <-time.After(time.Second):
				t.Fatal("terminal audit missing")
			}
			delete(event, "token")
			expected := map[string]string{"EOF": "SUCCEEDED", "disconnect": "CANCELLED", "revoked": "CANCELLED", "handshake-denied": "FAILED"}[mode]
			if event["outcome"] != expected {
				t.Fatalf("actual %s misreported: %#v", mode, event)
			}
			if mode == "revoked" && event["failureCode"] != "AuthorizationRevoked" {
				t.Fatal("revocation lost to Docker close error")
			}
		})
	}
}
