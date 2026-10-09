package auth

import (
	"context"
	"encoding/json"
	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/testutils"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

var auditFixtureSequence atomic.Uint64

func auditTicket(claim string) string {
	config.Config.ParsedPublicKey = testutils.ParseTestPublicKey()
	return testutils.CreateTokenWithPayload(map[string]interface{}{claim: map[string]interface{}{"version": 1, "issuedAt": time.Now().Unix(), "fixtureNonce": auditFixtureSequence.Add(1)}}, testutils.ParseTestPrivateKey())
}

func TestStreamAuditReportsActualTerminalStateWithAgentAuthentication(t *testing.T) {
	prior := config.Config
	defer func() { config.Config = prior }()
	var received map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, secret, ok := r.BasicAuth()
		if !ok || access != "test-agent" || secret != "test-agent-secret" {
			t.Error("missing trusted agent authentication")
		}
		if r.URL.Path != "/v2-beta/apiKeyDelegationCompletion" || r.URL.RawQuery != "" {
			t.Error("ticket entered URL")
		}
		received = make(map[string]string)
		json.NewDecoder(r.Body).Decode(&received)
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": true})
	}))
	defer server.Close()
	config.Config.PlatformURL = server.URL
	config.Config.PlatformAccessKey = "test-agent"
	config.Config.PlatformSecretKey = "test-agent-secret"
	config.Config.CompletionSpoolDir = testCompletionDir(t)
	for _, kind := range []string{"handshake", "EOF", "Docker", "revoked", "disconnect"} {
		audit := BeginStreamAudit(auditTicket("apiKeyDelegation"))
		if !audit.Ready() {
			t.Fatal("properly configured agent not ready")
		}
		if kind != "handshake" {
			audit.Authorized()
		}
		switch kind {
		case "EOF":
			audit.Succeed()
		case "Docker":
			audit.Fail("DockerFailure")
		case "revoked":
			audit.Cancel("AuthorizationRevoked")
			audit.Succeed()
		case "disconnect":
			audit.Cancel("ClientDisconnected")
			audit.Fail("DockerFailure")
		}
		if !audit.deliver(context.Background()) {
			t.Fatal("report failed")
		}
		expected := map[string]string{"handshake": "FAILED", "EOF": "SUCCEEDED", "Docker": "FAILED", "revoked": "CANCELLED", "disconnect": "CANCELLED"}[kind]
		if received["outcome"] != expected {
			t.Fatalf("%s misreported as %s", kind, received["outcome"])
		}
		if kind == "EOF" && received["failureCode"] != "" {
			t.Fatal("normal EOF carried a fake error")
		}
		if kind == "revoked" && received["failureCode"] != "AuthorizationRevoked" {
			t.Fatal("EOF overwrote revocation")
		}
	}
}

func TestStreamAuditRetryIsBoundedAndDoesNotRepeatExecution(t *testing.T) {
	prior := config.Config
	defer func() { config.Config = prior }()
	var attempts atomic.Int32
	var status atomic.Int32
	status.Store(503)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { attempts.Add(1); w.WriteHeader(int(status.Load())) }))
	defer server.Close()
	config.Config.PlatformURL = server.URL
	config.Config.PlatformAccessKey = "agent"
	config.Config.PlatformSecretKey = "secret"
	audit := BeginStreamAudit(auditTicket("apiKeyDelegation"))
	audit.Authorized()
	audit.Cancel("AuthorizationRevoked")
	var barriers int
	audit.pause = func(context.Context) bool { barriers++; return true }
	if audit.deliver(context.Background()) {
		t.Fatal("outage reported successful audit")
	}
	if attempts.Load() != 3 || barriers != 2 {
		t.Fatalf("unbounded attempts: %d / %d", attempts.Load(), barriers)
	}
	attempts.Store(0)
	status.Store(403)
	if audit.deliver(context.Background()) || attempts.Load() != 1 {
		t.Fatal("non-repairable authorization error retried")
	}
}

func TestLegacyUntracedStreamHasNoNewRequirementOrRequest(t *testing.T) {
	prior := config.Config
	defer func() { config.Config = prior }()
	config.Config.PlatformURL = ""
	config.Config.PlatformAccessKey = ""
	config.Config.PlatformSecretKey = ""
	legacy := BeginStreamAudit(auditTicket("hostUuid"))
	if !legacy.Ready() || !legacy.deliver(context.Background()) {
		t.Fatal("legacy behavior changed")
	}
	scoped := BeginStreamAudit(auditTicket("apiKeyDelegation"))
	if scoped.Ready() {
		t.Fatal("scoped execution allowed without authenticated completion channel")
	}
	traced := BeginStreamAudit(auditTicket("apiKeyAudit"))
	if traced.Ready() {
		t.Fatal("verified full trace escaped required durable audit")
	}
}
