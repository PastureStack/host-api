package delegation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type classifiedTransport func(*http.Request) (*http.Response, error)

func (f classifiedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClassifiedChecksPreserveFailClosedWithoutInventingRevocation(t *testing.T) {
	_, grant := fixture()
	allowed, _ := json.Marshal(answer(grant, "signed-ticket"))
	wrong := answer(grant, "signed-ticket")
	wrong["revision"] = grant.Revision + 1
	wrongBody, _ := json.Marshal(wrong)
	cases := []struct {
		name   string
		status int
		body   string
		want   Result
	}{
		{"allowed", 200, string(allowed), Allowed},
		{"policy-shrink", 403, `{"code":"ApiKeyPolicyChanged"}`, ConfirmedDenied},
		{"revoked", 403, `{"code":"ApiKeyRevoked"}`, ConfirmedDenied},
		{"expired", 401, `{"code":"ApiKeyExpired"}`, ConfirmedDenied},
		{"owner-lost", 403, `{"code":"OwnerPermissionDenied"}`, ConfirmedDenied},
		{"unclassified-403", 403, `{"code":"Forbidden"}`, Unknown},
		{"invalid-ticket-not-revoke", 403, `{"code":"ApiKeyDelegationInvalid"}`, Unknown},
		{"outage-with-code", 503, `{"code":"ApiKeyRevoked"}`, Unknown},
		{"redirect", 302, `{"code":"ApiKeyRevoked"}`, Unknown},
		{"bad-json", 403, `{"code":`, Unknown},
		{"trailing-json", 403, `{"code":"ApiKeyRevoked"}{}`, Unknown},
		{"wrong-binding", 200, string(wrongBody), Unknown},
		{"oversize", 403, strings.Repeat("x", 4097), Unknown},
		{"network", 0, "", Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := New("https://engine.example/v1")
			v.Now = func() time.Time { return time.Unix(900, 0) }
			v.Client.Transport = classifiedTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://engine.example/v2-beta/apiKeyDelegation/introspect" || r.Method != http.MethodPost || r.URL.RawQuery != "" {
					t.Error("classification changed trusted request binding")
				}
				var body map[string]string
				if json.NewDecoder(r.Body).Decode(&body) != nil || body["token"] != "signed-ticket" || len(body) != 1 {
					t.Error("classification did not send the original ticket")
				}
				if tc.status == 0 {
					return nil, errors.New("synthetic transport unavailable")
				}
				headers := http.Header{}
				if tc.status == http.StatusFound {
					headers.Set("Location", "https://foreign.example/introspect")
				}
				return &http.Response{StatusCode: tc.status, Header: headers, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			if got := v.CheckResult(context.Background(), "signed-ticket", grant); got != tc.want {
				t.Fatalf("classification=%d want=%d", got, tc.want)
			}
			if (v.Check(context.Background(), "signed-ticket", grant) == nil) != (tc.want == Allowed) {
				t.Fatal("ordinary authorization stopped failing closed")
			}
		})
	}
}

func TestClassifiedExpiryUsesPreviouslyVerifiedGrantWithoutNetwork(t *testing.T) {
	_, grant := fixture()
	v := New("https://engine.example")
	v.Now = func() time.Time { return time.Unix(grant.ExpiresAt, 0) }
	v.Client.Transport = classifiedTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("known expiry made a network request")
		return nil, errors.New("unexpected request")
	})
	if v.CheckResult(context.Background(), "signed-ticket", grant) != ConfirmedDenied || v.Check(context.Background(), "signed-ticket", grant) == nil {
		t.Fatal("expiry classification or fail-closed changed")
	}
	if v.CheckResult(context.Background(), "legacy", nil) != Allowed {
		t.Fatal("legacy grant semantics changed")
	}
	t.Run("expires-during-valid-response", func(t *testing.T) {
		var now atomic.Int64
		now.Store(900)
		v := New("https://engine.example")
		v.Now = func() time.Time { return time.Unix(now.Load(), 0) }
		v.Client.Transport = classifiedTransport(func(*http.Request) (*http.Response, error) {
			body, _ := json.Marshal(answer(grant, "signed-ticket"))
			now.Store(grant.ExpiresAt) // Valid-reply barrier, not elapsed wall time.
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
		})
		if v.CheckResult(context.Background(), "signed-ticket", grant) != ConfirmedDenied {
			t.Fatal("known expiry during valid reply became unknown or allowed")
		}
		now.Store(900)
		if v.Check(context.Background(), "signed-ticket", grant) == nil {
			t.Fatal("ordinary authorization allowed a grant expiring during its reply")
		}
	})
}

func TestClassifiedWatcherClosesAtControlledTickAndExpiryBarriers(t *testing.T) {
	_, grant := fixture()
	for _, mode := range []string{"confirmed", "unknown", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			v := New("https://engine.example")
			v.Now = func() time.Time { return time.Unix(900, 0) }
			v.Client.Transport = classifiedTransport(func(*http.Request) (*http.Response, error) {
				if mode == "unknown" {
					return nil, errors.New("synthetic outage")
				}
				return &http.Response{StatusCode: 403, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"code":"ApiKeyRevoked"}`))}, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ticks, expiry := make(chan time.Time), make(chan time.Time)
			denied := make(chan Result, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				v.runResult(ctx, "signed-ticket", grant, ticks, expiry, func(result Result) { denied <- result })
			}()
			if mode == "expiry" {
				expiry <- time.Unix(grant.ExpiresAt, 0)
			} else {
				ticks <- time.Unix(901, 0)
			}
			select {
			case got := <-denied:
				want := ConfirmedDenied
				if mode == "unknown" {
					want = Unknown
				}
				if got != want {
					t.Fatal("watcher lost the denial classification")
				}
			case <-ctx.Done():
				t.Fatal("watcher did not close at the barrier")
			}
			<-done
		})
	}
}
