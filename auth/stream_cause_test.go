package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/delegation"
	"github.com/PastureStack/host-api/testutils"
)

type causeFixture struct {
	audit       *StreamAudit
	raw         string
	state       atomic.Int32
	checks      atomic.Int32
	deliveries  atomic.Int32
	events      chan map[string]string
	rejectFirst bool
	beforeReply func(int32)
}

func newCauseFixture(t *testing.T, claim string, admitted bool) *causeFixture {
	t.Helper()
	prior := config.Config
	t.Cleanup(func() { config.Config = prior })
	config.Config.ParsedPublicKey = testutils.ParseTestPublicKey()
	config.Config.PlatformAccessKey = "unit-agent"
	config.Config.PlatformSecretKey = "unit-agent-secret"
	config.Config.CompletionSpoolDir = testCompletionDir(t)
	config.Config.HostUuidCheck = true
	config.Config.HostUuid = "unit-host"
	f := &causeFixture{events: make(chan map[string]string, 8)}
	now := time.Now().Unix()
	expires := now + 120
	envelope := map[string]interface{}{"version": 1, "issuedAt": now, "keyId": 12, "revision": 3,
		"principalId": 4, "accountId": 5, "requestId": "00000000-0000-4000-8000-000000000001",
		"targetType": "container", "targetId": "1i9", "operation": "logs", "expiresAt": expires}
	payload := map[string]interface{}{"hostUuid": "unit-host", "logs": map[string]interface{}{"Container": "unit-container", "Follow": true}}
	claims := map[string]interface{}{"exp": expires}
	if claim == delegation.Claim {
		envelope["payload"] = payload
		claims[delegation.Claim] = envelope
	} else {
		for key, value := range payload {
			claims[key] = value
		}
		if claim == "apiKeyAudit" {
			claims[claim] = envelope
		}
	}
	f.raw = testutils.CreateTokenWithPayload(claims, testutils.ParseTestPrivateKey())
	digest := sha256.Sum256([]byte(f.raw))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2-beta/apiKeyDelegation/introspect":
			f.checks.Add(1)
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["token"] != f.raw || r.URL.RawQuery != "" {
				t.Error("final check lost original signed-ticket binding")
			}
			if f.state.Load() == 1 {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"code": "ApiKeyPolicyChanged"})
				return
			}
			if f.state.Load() == 2 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"allowed": true, "keyId": 12, "revision": 3,
				"targetType": "container", "targetId": "1i9", "operation": "logs", "expiresAt": expires,
				"tokenDigest": hex.EncodeToString(digest[:])})
		case "/v2-beta/apiKeyDelegationCompletion":
			user, secret, ok := r.BasicAuth()
			if !ok || user != "unit-agent" || secret != "unit-agent-secret" {
				t.Error("completion lost host-agent authentication")
			}
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["token"] != f.raw {
				t.Error("completion changed original signed ticket")
			}
			delete(body, "token") // Never include the signed fixture ticket in diagnostics.
			n := f.deliveries.Add(1)
			f.events <- body
			if f.beforeReply != nil {
				f.beforeReply(n)
			}
			if f.rejectFirst && n == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			json.NewEncoder(w).Encode(map[string]bool{"accepted": true})
		default:
			t.Error("unexpected endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	config.Config.PlatformURL = server.URL
	f.audit = BeginStreamAudit(f.raw)
	if admitted {
		if _, valid := GetAndCheckStreamToken(f.raw, "/v2-beta/logs/"); !valid {
			t.Fatal("valid signed fixture failed admission")
		}
	}
	if !f.audit.Ready() {
		t.Fatal("private completion fixture not ready")
	}
	if admitted {
		f.audit.Authorized()
	}
	f.checks.Store(0)
	return f
}

func (f *causeFixture) event(t *testing.T, outcome, code string) {
	t.Helper()
	select {
	case event := <-f.events:
		if event["outcome"] != outcome || event["failureCode"] != code {
			t.Fatalf("terminal outcome=%s code=%s", event["outcome"], event["failureCode"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminal evidence missing")
	}
}

func TestStreamCauseProxyFirstRechecksOriginalSignedGrant(t *testing.T) {
	f := newCauseFixture(t, delegation.Claim, true)
	// The Proxy transport-close barrier precedes any Host watcher callback.
	f.state.Store(1)
	f.audit.Cancel("ClientDisconnected")
	f.audit.Fail("DockerFailure") // Cancellation-induced pipe error is secondary.
	f.audit.Report()
	f.event(t, "CANCELLED", "AuthorizationRevoked")
	if f.checks.Load() != 1 {
		t.Fatal("transport cancellation did not receive exactly one final check")
	}
}

func TestStreamCauseHostFirstCannotBeDowngradedByDisconnect(t *testing.T) {
	f := newCauseFixture(t, delegation.Claim, true)
	f.audit.authorizationResult(delegation.ConfirmedDenied)
	f.audit.Cancel("ClientDisconnected")
	f.audit.authorizationResult(delegation.Unknown)
	f.audit.Fail("DockerFailure")
	f.audit.Succeed()
	f.audit.Report()
	f.event(t, "CANCELLED", "AuthorizationRevoked")
	if f.checks.Load() != 0 {
		t.Fatal("known denial was needlessly rechecked")
	}
}

func TestStreamCauseGenuineClientDisconnectWithLiveGrant(t *testing.T) {
	f := newCauseFixture(t, delegation.Claim, true)
	f.audit.Cancel("ClientDisconnected")
	f.audit.Report()
	f.event(t, "CANCELLED", "ClientDisconnected")
	if f.checks.Load() != 1 {
		t.Fatal("live-grant disconnect classification skipped the final check")
	}
}

func TestStreamCauseUnavailableEngineIsNotConfirmedRevocation(t *testing.T) {
	f := newCauseFixture(t, delegation.Claim, true)
	f.state.Store(2)
	f.audit.Cancel("ClientDisconnected")
	f.audit.Report()
	f.event(t, "CANCELLED", "StreamCancelled")
}

func TestStreamCauseExpiryOfPreviouslyAdmittedSignedGrant(t *testing.T) {
	f := newCauseFixture(t, delegation.Claim, true)
	token, err := ParseToken(f.raw, config.Config.ParsedPublicKey)
	if err != nil {
		t.Fatal("signed expiry fixture invalid")
	}
	claims, _ := MapClaims(token)
	grant, err := delegation.Parse(map[string]interface{}(claims))
	if err != nil || grant == nil {
		t.Fatal("signed grant missing")
	}
	v := delegation.New(config.Config.PlatformURL)
	v.Now = func() time.Time { return time.Unix(grant.ExpiresAt, 0) }
	f.audit.recheck = func(ctx context.Context) delegation.Result { return v.CheckResult(ctx, f.raw, grant) }
	f.audit.Cancel("ClientDisconnected")
	f.audit.Report()
	f.event(t, "CANCELLED", "AuthorizationRevoked")
	if f.checks.Load() != 0 {
		t.Fatal("known local expiry contacted Engine")
	}
}

func TestStreamCauseCompletedEOFAndBackendFailureRemainTerminal(t *testing.T) {
	for _, mode := range []string{"EOF", "DockerFailure"} {
		t.Run(mode, func(t *testing.T) {
			f := newCauseFixture(t, delegation.Claim, true)
			outcome, code := "SUCCEEDED", ""
			if mode == "EOF" {
				f.audit.Succeed()
			} else {
				f.audit.Fail(mode)
				outcome, code = "FAILED", mode
			}
			f.audit.Cancel("ClientDisconnected")
			f.audit.authorizationResult(delegation.ConfirmedDenied)
			f.audit.Report()
			f.event(t, outcome, code)
			if f.checks.Load() != 0 {
				t.Fatal("completed backend work received a new authorization requirement")
			}
		})
	}
}

func TestStreamCauseOrdinaryJWTFullTraceAndHandshakeHaveNoFinalCheck(t *testing.T) {
	for _, claim := range []string{"legacy", "apiKeyAudit", delegation.Claim} {
		t.Run(claim, func(t *testing.T) {
			admitted := claim != delegation.Claim
			f := newCauseFixture(t, claim, admitted)
			if admitted {
				f.audit.Cancel("ClientDisconnected")
			}
			f.audit.Report()
			if claim == "apiKeyAudit" {
				f.event(t, "CANCELLED", "ClientDisconnected")
			} else if claim == delegation.Claim {
				f.event(t, "FAILED", "HandshakeDenied")
			} else if f.deliveries.Load() != 0 {
				t.Fatal("ordinary JWT acquired an audit requirement")
			}
			if f.checks.Load() != 0 {
				t.Fatal("unscoped or unadmitted stream acquired a final check")
			}
		})
	}
}

func TestStreamCauseFinalizationHasNoNetworkMutexAndFreezesOnce(t *testing.T) {
	f := newCauseFixture(t, delegation.Claim, true)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.audit.recheck = func(ctx context.Context) delegation.Result {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 7*time.Second {
			t.Error("final check escaped the existing total report budget")
		}
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return delegation.Unknown
	}
	f.audit.Cancel("ClientDisconnected")
	go func() { f.audit.Report(); close(done) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("final check did not reach its entry barrier")
	}
	callback := make(chan struct{})
	go func() { f.audit.authorizationResult(delegation.ConfirmedDenied); close(callback) }()
	select {
	case <-callback:
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("network check held the audit mutex")
	}
	close(release)
	<-done
	f.event(t, "CANCELLED", "AuthorizationRevoked")
	f.audit.Cancel("ClientDisconnected")
	f.audit.Fail("DockerFailure")
	f.audit.Succeed()
	f.audit.Report()
	if record := f.audit.record("TERMINAL"); record.Outcome != "CANCELLED" || record.FailureCode != "AuthorizationRevoked" || f.deliveries.Load() != 1 {
		t.Fatal("late callback or repeated Report changed the frozen terminal")
	}
}

func TestStreamCauseEvidenceRetryKeepsSameFrozenTicketAndOutcome(t *testing.T) {
	f := newCauseFixture(t, delegation.Claim, true)
	f.rejectFirst = true
	f.beforeReply = func(n int32) {
		if n == 1 {
			record, _, err := f.audit.queue.read(f.audit.queue.path(completionID(f.raw)))
			if err != nil || record.Token != f.raw || record.State != "TERMINAL" || record.FailureCode != "AuthorizationRevoked" {
				t.Error("first delivery did not use the one persisted terminal")
			}
			f.audit.Cancel("ClientDisconnected")
			f.audit.Fail("DockerFailure")
		}
	}
	f.audit.authorizationResult(delegation.ConfirmedDenied)
	f.audit.Report()
	f.event(t, "CANCELLED", "AuthorizationRevoked")
	f.event(t, "CANCELLED", "AuthorizationRevoked")
	if f.deliveries.Load() != 2 || f.checks.Load() != 0 {
		t.Fatal("retry changed terminal identity or repeated stream authorization")
	}
}
