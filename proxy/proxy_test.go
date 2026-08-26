package proxy

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/PastureStack/websocket-proxy/common"

	. "gopkg.in/check.v1"
)

const host = "127.0.0.1:23425"

func Test(t *testing.T) {
	TestingT(t)
}

func TestProxyTargetValidation(t *testing.T) {
	for _, raw := range []string{"file:///etc/passwd", "http://user:secret@example.test", "http:///missing-host"} {
		target, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateTargetURL(target); err == nil {
			t.Fatalf("unsafe target was accepted: %s", raw)
		}
	}
	target, err := url.Parse("http://127.0.0.1:8080/health")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateTargetURL(target); err != nil {
		t.Fatalf("valid target was rejected: %v", err)
	}
}

func TestSetContentLengthRejectsNegativeValue(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "http://127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Length", "-1")
	if _, err := setContentLength(request); err == nil {
		t.Fatal("negative content length was accepted")
	}
}

func TestHijackedHTTPSUsesCertificateVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if connection, err := dialProxyTarget(target); err == nil {
		connection.Close()
		t.Fatal("self-signed HTTPS target was accepted without a trusted certificate")
	}
}

func TestProxyTargetAddressAddsDefaultPort(t *testing.T) {
	for raw, expected := range map[string]string{
		"http://example.test/path":  "example.test:80",
		"https://example.test/path": "example.test:443",
		"http://[::1]/path":         "[::1]:80",
	} {
		target, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if actual := proxyTargetAddress(target); actual != expected {
			t.Fatalf("unexpected target address for %s: %s", raw, actual)
		}
	}
}

func TestProxyLogTargetRedactsCredentialsAndQuery(t *testing.T) {
	target, err := url.Parse("https://user:secret@example.test/path?token=secret#fragment")
	if err != nil {
		t.Fatal(err)
	}
	logged := proxyLogTarget(target)
	if logged != "https://example.test/path" {
		t.Fatalf("unexpected redacted target: %q", logged)
	}
}

func TestSafeLogValueProducesSingleRecord(t *testing.T) {
	if got := safeLogValue("first\r\nforged\nthird"); got != "first forged third" {
		t.Fatalf("unexpected safe log value: %q", got)
	}
}

type ProxyTestSuite struct {
}

var _ = Suite(&ProxyTestSuite{})

func (s *ProxyTestSuite) TestPost(c *C) {
	input := make(chan string)
	output := make(chan common.Message)

	handler := &Handler{}
	go handler.Handle("key", "init", input, output)

	input <- marshal(c, common.HTTPMessage{
		Method: "POST",
		URL:    "http://" + host + "/foo",
		Headers: map[string][]string{
			"Content-Length": []string{"6"},
		},
		Body: []byte("foo"),
	})
	input <- marshal(c, common.HTTPMessage{
		Body: []byte("bar"),
	})
	input <- marshal(c, common.HTTPMessage{
		EOF: true,
	})

	var response common.HTTPMessage
	unmarshal(c, <-output, &response)
	c.Assert(response.Code, Equals, 200)
	response = common.HTTPMessage{}

	//Second message will have the payload
	unmarshal(c, <-output, &response)
	c.Assert(string(response.Body), Equals, "foobar")
}

func unmarshal(c *C, msg common.Message, httpMessage *common.HTTPMessage) {
	if err := json.Unmarshal([]byte(msg.Body), httpMessage); err != nil {
		c.Fatal(err)
	}
}

func marshal(c *C, obj interface{}) string {
	bytes, err := json.Marshal(obj)
	if err != nil {
		c.Fatal(err)
	}
	return string(bytes)
}

func (s *ProxyTestSuite) SetUpSuite(c *C) {
	listener, err := net.Listen("tcp", host)
	c.Assert(err, IsNil)

	go http.Serve(listener, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		bytes, err := io.ReadAll(r.Body)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		rw.Write(bytes)
	}))
}
