package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/delegation"
	"github.com/PastureStack/websocket-proxy/common"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/golang/glog"
)

// StreamAudit reports evidence with the existing agent credential. Signature-only
// ticket validation below selects audit-only work; it never authorizes a stream.
type StreamAudit struct {
	mu                                    sync.Mutex
	enabled, required, cancelled          bool
	authorized, completed, frozen         bool
	reportOnce                            sync.Once
	recheck                               func(context.Context) delegation.Result
	token, endpoint, accessKey, secretKey string
	outcome, failureCode                  string
	client                                *http.Client
	pause                                 func(context.Context) bool
	queue                                 *completionSpool
	expiresAt                             int64
}

const AuditUnavailableWire = "AuditUnavailable:503"

func (a *StreamAudit) Unavailable(key string, response chan<- common.Message) {
	a.Fail("AuditUnavailable")
	response <- common.Message{Key: key, Type: common.Close, Body: AuditUnavailableWire}
}

func BeginStreamAudit(raw string) *StreamAudit {
	a := &StreamAudit{token: raw, outcome: "FAILED", failureCode: "HandshakeDenied", accessKey: config.Config.PlatformAccessKey, secretKey: config.Config.PlatformSecretKey,
		client: &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	a.pause = func(ctx context.Context) bool {
		timer := time.NewTimer(150 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	if raw == "" || len(raw) > delegation.MaxTokenBytes {
		return a
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithJSONNumber()).ParseUnverified(raw, claims); err != nil {
		return a
	}
	_, a.required = claims[delegation.Claim]
	_, legacyTrace := claims["apiKeyAudit"]
	a.enabled = a.required || legacyTrace
	if a.enabled {
		// Do not let forged ticket claims fill the private bounded spool. Expiry
		// remains mandatory in normal stream authorization, not audit evidence.
		if _, err := jwt.Parse(raw, func(*jwt.Token) (interface{}, error) { return config.Config.ParsedPublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation()); err != nil {
			a.enabled = false
			return a
		}
	}
	if a.required && a.enabled {
		if grant, err := delegation.Parse(map[string]interface{}(claims)); err == nil && grant != nil {
			verifier := delegation.New(config.Config.PlatformURL)
			a.recheck = func(ctx context.Context) delegation.Result { return verifier.CheckResult(ctx, raw, grant) }
		}
	}
	if envelope, ok := claims["apiKeyAudit"].(map[string]interface{}); ok {
		a.expiresAt = receiptExpiry(envelope)
	}
	if envelope, ok := claims[delegation.Claim].(map[string]interface{}); ok {
		a.expiresAt = receiptExpiry(envelope)
	}
	u, err := url.Parse(config.Config.PlatformURL)
	if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
		u.Path = "/v2-beta/apiKeyDelegationCompletion"
		u.RawPath = ""
		a.endpoint = u.String()
	}
	return a
}

func (a *StreamAudit) Ready() bool {
	if !a.enabled {
		return true
	}
	if a.endpoint == "" || a.accessKey == "" || a.secretKey == "" || a.expiresAt <= time.Now().Unix() {
		return false
	}
	queue, err := configuredCompletionSpool()
	if err == nil {
		err = queue.reserve(a.record("PENDING"))
	}
	if err != nil {
		return false
	}
	a.queue = queue
	return true
}
func (a *StreamAudit) Enabled() bool { return a.enabled }
func (a *StreamAudit) Authorized() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.frozen || a.completed || a.cancelled {
		return
	}
	a.authorized = true
	a.outcome = "CANCELLED"
	a.failureCode = "ClientDisconnected"
}
func (a *StreamAudit) Succeed() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.cancelled && !a.frozen && !a.completed {
		a.outcome = "SUCCEEDED"
		a.failureCode = ""
		a.completed = true
	}
}
func (a *StreamAudit) Fail(code string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.cancelled && !a.frozen && !a.completed {
		a.outcome = "FAILED"
		a.failureCode = code
		a.completed = true
	}
}
func (a *StreamAudit) Cancel(code string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.frozen || a.completed || (a.cancelled && cancellationPriority(code) <= cancellationPriority(a.failureCode)) {
		return
	}
	a.cancelled = true
	a.outcome = "CANCELLED"
	a.failureCode = code
}

func cancellationPriority(code string) int {
	switch code {
	case "AuthorizationRevoked":
		return 3
	case "StreamCancelled":
		return 2
	default:
		return 1
	}
}

func (a *StreamAudit) finalize(ctx context.Context) {
	a.mu.Lock()
	check := a.recheck
	transport := a.required && a.authorized && !a.completed && !a.frozen &&
		a.outcome == "CANCELLED" && a.failureCode != "AuthorizationRevoked"
	a.mu.Unlock()
	if transport {
		result := delegation.Unknown
		if check != nil {
			result = check(ctx) // Never hold the audit mutex during network I/O.
		}
		a.authorizationResult(result)
	}
	a.mu.Lock()
	a.frozen = true
	a.mu.Unlock()
}

func (a *StreamAudit) Report() {
	if !a.enabled {
		return
	}
	a.reportOnce.Do(func() {
		// Rechecking and delivery share the existing total report budget. The
		// stream is already closed; this cannot renew or reopen its authority.
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		a.finalize(ctx)
		queue := a.queue
		if queue == nil {
			queue, _ = configuredCompletionSpool()
		}
		if queue == nil || queue.complete(a.record("TERMINAL")) != nil {
			glog.Warning("API key stream terminal evidence could not be persisted")
			return
		}
		if !queue.deliverOne(ctx, completionID(a.token)) {
			glog.Warning("API key stream terminal audit remains pending delivery")
		}
	})
}

func (a *StreamAudit) deliver(ctx context.Context) bool {
	if !a.enabled {
		return true
	}
	if a.endpoint == "" || a.accessKey == "" || a.secretKey == "" {
		return false
	}
	a.mu.Lock()
	body := map[string]string{"token": a.token, "outcome": a.outcome}
	if a.failureCode != "" {
		body["failureCode"] = a.failureCode
	}
	a.mu.Unlock()
	encoded, _ := json.Marshal(body)
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(encoded))
		if err != nil {
			return false
		}
		req.SetBasicAuth(a.accessKey, a.secretKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := a.client.Do(req)
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && readErr == nil && len(data) <= 4096 {
				var result map[string]interface{}
				if json.Unmarshal(data, &result) == nil && result["accepted"] == true {
					return true
				}
			}
			// Authentication/validation errors cannot be repaired by repeating a report.
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return false
			}
		}
		if attempt < 2 && !a.pause(ctx) {
			return false
		}
	}
	return false
}
