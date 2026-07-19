package platformapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientDiscoversAndCreatesResources(t *testing.T) {
	const accessKey = "access"
	const secretKey = "secret"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != accessKey || password != secretKey {
			t.Fatalf("unexpected basic authentication")
		}
		switch request.URL.Path {
		case "/v2-beta":
			response.Header().Set("X-API-Schemas", server.URL+"/v2-beta/schemas")
		case "/v2-beta/schemas":
			fmt.Fprintf(response, `{"data":[
				{"id":"containerEvent","collectionMethods":["POST"],"links":{"collection":%q}},
				{"id":"hostApiProxyToken","pluralName":"hostApiProxyTokens","collectionMethods":["POST"],"links":{"self":%q}}
			]}`, server.URL+"/v2-beta/containerEvents", server.URL+"/v2-beta/schemas/hostApiProxyToken")
		case "/v2-beta/containerEvents":
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("unexpected container event request")
			}
			fmt.Fprint(response, `{"externalId":"container-1"}`)
		case "/v2-beta/hostApiProxyTokens":
			fmt.Fprint(response, `{"token":"token-1","url":"wss://proxy.example.test/connect"}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client, err := NewClient(ClientOpts{URL: server.URL + "/v2-beta", AccessKey: accessKey, SecretKey: secretKey})
	if err != nil {
		t.Fatal(err)
	}
	event, err := client.ContainerEvent.Create(&ContainerEvent{ExternalID: "container-1"})
	if err != nil {
		t.Fatal(err)
	}
	if event.ExternalID != "container-1" {
		t.Fatalf("unexpected container event: %#v", event)
	}
	token, err := client.HostAPIProxyToken.Create(&HostAPIProxyToken{ReportedUUID: "host-1"})
	if err != nil {
		t.Fatal(err)
	}
	if token.Token != "token-1" || token.URL == "" {
		t.Fatalf("unexpected proxy token: %#v", token)
	}
}

func TestClientRejectsCrossOriginSchema(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("X-API-Schemas", other.URL+"/schemas")
	}))
	defer server.Close()

	_, err := NewClient(ClientOpts{URL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "cross-origin schema") {
		t.Fatalf("expected cross-origin schema rejection, got %v", err)
	}
}

func TestClientRejectsCrossOriginCollection(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-API-Schemas", request.URL.String())
		fmt.Fprintf(response, `{"data":[
			{"id":"containerEvent","collectionMethods":["POST"],"links":{"collection":%q}},
			{"id":"hostApiProxyToken","collectionMethods":["POST"],"links":{"collection":%q}}
		]}`, other.URL+"/events", request.URL.String()+"/tokens")
	}))
	defer server.Close()

	_, err := NewClient(ClientOpts{URL: server.URL + "/v2-beta"})
	if err == nil || !strings.Contains(err.Error(), "cross-origin containerEvent") {
		t.Fatalf("expected cross-origin collection rejection, got %v", err)
	}
}

func TestClientBoundsErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(response, strings.Repeat("x", maxErrorBytes+1))
	}))
	defer server.Close()

	_, err := NewClient(ClientOpts{URL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected bounded response error, got %v", err)
	}
}

func TestClientRejectsURLQueryAndFragment(t *testing.T) {
	for _, raw := range []string{
		"https://platform.example.test/v2-beta?token=secret",
		"https://platform.example.test/v2-beta#fragment",
	} {
		if _, err := NewClient(ClientOpts{URL: raw}); err == nil {
			t.Fatalf("unsafe control-platform URL was accepted: %s", raw)
		}
	}
}

func TestAPIErrorDoesNotExposeURLQuery(t *testing.T) {
	err := (&APIError{
		URL:    "https://platform.example.test/v2-beta?token=secret",
		Status: "401 Unauthorized",
	}).Error()
	if strings.Contains(err, "secret") || strings.Contains(err, "token=") {
		t.Fatalf("API error exposed URL query: %q", err)
	}
}

func TestCreateBoundsRequestBody(t *testing.T) {
	requestClient := &client{
		httpClient: &http.Client{},
		collection: "https://platform.example.test/v2-beta/containerEvents",
	}
	err := requestClient.create(map[string]string{"data": strings.Repeat("x", maxRequestBytes+1)}, &map[string]interface{}{})
	if err == nil || !strings.Contains(err.Error(), "request body exceeds") {
		t.Fatalf("expected bounded request error, got %v", err)
	}
}
