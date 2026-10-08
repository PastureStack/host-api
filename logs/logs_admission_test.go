package logs

import (
	"errors"
	"github.com/PastureStack/host-api/auth"
	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/testutils"
	"github.com/PastureStack/websocket-proxy/common"
	docker "github.com/fsouza/go-dockerclient"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifiedFullKeyAuditAdmissionPreventsLogsSideEffects(t *testing.T) {
	prior := config.Config
	defer func() { config.Config = prior }()
	config.Config.ParsedPublicKey = testutils.ParseTestPublicKey()
	config.Config.HostUuid = "h1"
	config.Config.HostUuidCheck = true
	config.Config.PlatformURL = "http://127.0.0.1:1"
	config.Config.PlatformAccessKey = "agent"
	config.Config.PlatformSecretKey = "secret"
	for _, mode := range []string{"full", "unwritable"} {
		t.Run(mode, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(parent, "completion-spool")
			config.Config.CompletionSpoolDir = dir
			ticket := func(nonce interface{}) string {
				return testutils.CreateTokenWithPayload(map[string]interface{}{"hostUuid": "h1", "apiKeyAudit": map[string]interface{}{"version": 1, "issuedAt": time.Now().Unix(), "fixture": nonce}, "logs": map[string]interface{}{"Container": "must-not-read-logs", "Follow": true}}, testutils.ParseTestPrivateKey())
			}
			if mode == "full" {
				for i := 0; i < 128; i++ {
					if !auth.BeginStreamAudit(ticket(i)).Ready() {
						t.Fatal("fixture could not fill exact bounded queue")
					}
				}
			} else {
				if err := os.WriteFile(dir, []byte("fixture blocker"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			handler := &LogsHandler{dockerClient: func() (*docker.Client, error) { called = true; return nil, errors.New("must not reach Docker") }}
			response := make(chan common.Message, 4)
			handler.Handle("fixture", "/v2-beta/logs/?token="+ticket("attempt"), make(chan string), response)
			if called {
				t.Fatal("audit admission failure read Docker logs")
			}
			message := <-response
			if message.Type != common.Close || message.Body != auth.AuditUnavailableWire {
				t.Fatal("unavailable audit was misrepresented as permission denial")
			}
		})
	}
}
