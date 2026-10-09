package exec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PastureStack/host-api/auth"
	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/testutils"
	docker "github.com/fsouza/go-dockerclient"
)

func TestExecAuditRequiresActualExitResult(t *testing.T) {
	prior := config.Config
	defer func() { config.Config = prior }()
	var result map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result = make(map[string]string)
		json.NewDecoder(r.Body).Decode(&result)
		delete(result, "token")
		json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
	}))
	defer server.Close()
	config.Config.PlatformURL = server.URL
	config.Config.PlatformAccessKey = "agent"
	config.Config.PlatformSecretKey = "secret"
	config.Config.ParsedPublicKey = testutils.ParseTestPublicKey()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	config.Config.CompletionSpoolDir = filepath.Join(parent, "completion-spool")
	for _, candidate := range []struct {
		name          string
		inspect       *docker.ExecInspect
		err           error
		outcome, code string
	}{
		{"zero", &docker.ExecInspect{}, nil, "SUCCEEDED", ""},
		{"nonzero", &docker.ExecInspect{ExitCode: 2}, nil, "FAILED", "StreamFailed"},
		{"still-running", &docker.ExecInspect{Running: true}, nil, "CANCELLED", "StreamCancelled"},
		{"inspect-failed", nil, context.Canceled, "FAILED", "DockerFailure"},
	} {
		raw := testutils.CreateTokenWithPayload(map[string]interface{}{"apiKeyAudit": map[string]interface{}{"version": 1, "issuedAt": time.Now().Unix(), "fixture": candidate.name}}, testutils.ParseTestPrivateKey())
		audit := auth.BeginStreamAudit(raw)
		audit.Authorized()
		finishExecAudit(audit, candidate.inspect, candidate.err)
		audit.Report()
		if result["outcome"] != candidate.outcome || result["failureCode"] != candidate.code {
			t.Fatalf("%s: wrong terminal result %#v", candidate.name, result)
		}
	}
}
