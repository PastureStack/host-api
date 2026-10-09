package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PastureStack/host-api/config"
	jwt "github.com/golang-jwt/jwt/v5"
)

func testCompletionDir(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "completion-spool")
}

func TestCompletionSpoolPrivateRestartReplaysTerminalAndInterruptedPending(t *testing.T) {
	prior := config.Config
	defer func() { config.Config = prior }()
	dir := testCompletionDir(t)
	config.Config.CompletionSpoolDir = dir
	config.Config.PlatformAccessKey = "test-agent"
	config.Config.PlatformSecretKey = "never-persist-this-agent-secret"
	var unavailable atomic.Bool
	unavailable.Store(true)
	events := make(chan map[string]string, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unavailable.Load() {
			w.WriteHeader(503)
			return
		}
		user, secret, ok := r.BasicAuth()
		if !ok || user != "test-agent" || secret != config.Config.PlatformSecretKey {
			t.Error("replay lost authenticated agent source")
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		delete(body, "token")
		events <- body
		json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
	}))
	defer server.Close()
	config.Config.PlatformURL = server.URL
	audit := BeginStreamAudit(auditTicket("apiKeyDelegation"))
	if !audit.Ready() {
		t.Fatal("reservation failed")
	}
	audit.Authorized()
	audit.Cancel("AuthorizationRevoked")
	// Persist exactly the same terminal state as Report, then emulate process loss before delivery.
	if err := audit.queue.complete(audit.record("TERMINAL")); err != nil {
		t.Fatal(err)
	}
	audit.Report() // An actual failed delivery must leave the immutable disk record.
	interrupted := BeginStreamAudit(auditTicket("apiKeyAudit"))
	if !interrupted.Ready() {
		t.Fatal("pending reservation failed")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("evidence missing")
	}
	for _, entry := range entries {
		info, _ := entry.Info()
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatal("ticket file is not private")
		}
		data, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
		if strings.Contains(string(data), config.Config.PlatformSecretKey) {
			t.Fatal("agent secret persisted")
		}
	}
	if info, _ := os.Stat(dir); runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		t.Fatal("queue directory is not private")
	}
	restarted, err := openCompletionSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.recoverPending(); err != nil {
		t.Fatal(err)
	}
	unavailable.Store(false)
	restarted.replayOnce(context.Background())
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case event := <-events:
			seen[event["failureCode"]] = true
			if event["outcome"] != "CANCELLED" {
				t.Fatal("restart fabricated success")
			}
		case <-time.After(time.Second):
			t.Fatal("restart did not replay")
		}
	}
	if !seen["AuthorizationRevoked"] || !seen["StreamCancelled"] {
		t.Fatal("terminal outcome was overwritten or pending was not interrupted")
	}
	entries, _ = os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("acknowledged records remained queued")
	}
}

func TestForgedTicketCannotFillCompletionSpool(t *testing.T) {
	prior := config.Config
	defer func() { config.Config = prior }()
	config.Config.CompletionSpoolDir = testCompletionDir(t)
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"apiKeyDelegation": map[string]interface{}{"version": 1, "issuedAt": time.Now().Unix()}})
	raw, _ := forged.SignedString([]byte("untrusted-client"))
	audit := BeginStreamAudit(raw)
	audit.Report()
	entries, _ := os.ReadDir(config.Config.CompletionSpoolDir)
	if audit.Enabled() || len(entries) != 0 {
		t.Fatal("unverified claims persisted ticket evidence")
	}
}

func TestCompletionSpoolCapacityDeniesNewScopedStreamAndTTLReclaimsOnlyOwnFiles(t *testing.T) {
	prior := config.Config
	defer func() { config.Config = prior }()
	dir := testCompletionDir(t)
	config.Config.CompletionSpoolDir = dir
	config.Config.PlatformURL = "http://127.0.0.1:1"
	config.Config.PlatformAccessKey = "agent"
	config.Config.PlatformSecretKey = "secret"
	queue, err := configuredCompletionSpool()
	if err != nil {
		t.Fatal(err)
	}
	queue.maxRecords = 1
	first := BeginStreamAudit(auditTicket("apiKeyDelegation"))
	if !first.Ready() {
		t.Fatal("initial reservation failed")
	}
	second := BeginStreamAudit(auditTicket("apiKeyAudit"))
	second.required = true
	if second.Ready() {
		t.Fatal("full spool allowed new scoped work and could drop its outcome")
	}
	queue.now = func() time.Time { return time.Unix(first.expiresAt, 0) }
	if err := queue.recoverPending(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("expired ticket retained")
	}
	queue.now = time.Now
	if !second.Ready() {
		t.Fatal("TTL did not recover bounded capacity")
	}
	legacy := BeginStreamAudit(auditTicket("apiKeyAudit"))
	if legacy.Ready() {
		t.Fatal("verified full trace bypassed durable admission")
	}
	queue.maxRecords = 256
	queue.maxBytes = completionMaxRecordBytes - 1
	if first.Ready() {
		t.Fatal("byte capacity bound did not reject scoped work")
	}
}

func TestCompletionSpoolImmutableTerminalAndUnsafePathFailClosed(t *testing.T) {
	dir := testCompletionDir(t)
	queue, err := openCompletionSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	record := completionRecord{Version: 1, Token: auditTicket("apiKeyDelegation"), State: "TERMINAL", Outcome: "FAILED", FailureCode: "DockerFailure", ExpiresAt: time.Now().Unix() + 3600}
	if err := queue.complete(record); err != nil {
		t.Fatal(err)
	}
	record.Outcome = "SUCCEEDED"
	record.FailureCode = ""
	if err := queue.complete(record); err != nil {
		t.Fatal(err)
	}
	stored, _, err := queue.read(queue.path(completionID(record.Token)))
	if err != nil || stored.Outcome != "FAILED" {
		t.Fatal("retry overwrote first terminal evidence")
	}
	if runtime.GOOS != "windows" {
		alias := filepath.Join(t.TempDir(), "completion-spool")
		if err := os.Symlink(dir, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := openCompletionSpool(alias); err == nil {
			t.Fatal("symlink spool accepted")
		}
		if err := os.Chmod(queue.path(completionID(record.Token)), 0644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := queue.read(queue.path(completionID(record.Token))); err == nil {
			t.Fatal("public ticket file accepted")
		}
	}
}

func TestCompletionSpoolRejectsBroadConfigurationWithoutChangingDirectoryPermissions(t *testing.T) {
	dir := t.TempDir()
	before, _ := os.Stat(dir)
	if _, err := openCompletionSpool(dir); err == nil {
		t.Fatal("non-dedicated directory accepted")
	}
	after, _ := os.Stat(dir)
	if before.Mode() != after.Mode() {
		t.Fatal("unsafe target permissions changed")
	}
	if _, err := openCompletionSpool(filepath.VolumeName(dir) + string(os.PathSeparator)); err == nil {
		t.Fatal("filesystem root accepted")
	}
}
