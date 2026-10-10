package main

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/PastureStack/host-api/platformapi"
)

func TestTraditionalChineseOperatorMessage(t *testing.T) {
	if got := operatorMessage("zh-TW", "start"); got != "PastureStack 主機 API 已準備連線" {
		t.Fatalf("unexpected zh-TW message: %q", got)
	}
}

func TestProxyConnectionURLValidatesAndEscapesToken(t *testing.T) {
	result, err := proxyConnectionURL(&platformapi.HostAPIProxyToken{
		URL:   "wss://proxy.example.test/connect?mode=host&token=old",
		Token: "a+b&c",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(result)
	query := parsed.Query()
	if query.Get("token") != "a+b&c" || query.Get("mode") != "host" || query.Get("hostApiVersion") != "0.38.5" || query.Get("hostApiCapabilities") != "key-audit-v1,key-delegation-v1" {
		t.Fatal("proxy connection did not preserve authority and declare producer capabilities")
	}
	for _, response := range []*platformapi.HostAPIProxyToken{
		{URL: "https://proxy.example.test/connect", Token: "token"},
		{URL: "wss://user:pass@proxy.example.test/connect", Token: "token"},
		{URL: "wss://proxy.example.test/connect#fragment", Token: "token"},
		{URL: "wss://proxy.example.test/connect", Token: ""},
		{URL: "wss://proxy.example.test/connect", Token: strings.Repeat("x", maxProxyTokenBytes+1)},
	} {
		if _, err := proxyConnectionURL(response); err == nil {
			t.Fatalf("unsafe proxy response was accepted: %#v", response)
		}
	}
}

func TestDefaultVersionIsNumeric(t *testing.T) {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version) {
		t.Fatalf("version must be MAJOR.MINOR.PATCH with no suffix: %q", version)
	}
}
