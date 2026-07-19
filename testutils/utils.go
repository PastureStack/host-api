package testutils

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/PastureStack/websocket-proxy/proxy"
	jwt "github.com/golang-jwt/jwt/v5"
)

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
	testKeyErr  error
)

func runtimeTestKey() *rsa.PrivateKey {
	testKeyOnce.Do(func() {
		testKey, testKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if testKeyErr != nil {
		panic(testKeyErr)
	}
	return testKey
}

func ParseTestPrivateKey() interface{} {
	return runtimeTestKey()
}

func ParseTestPublicKey() interface{} {
	return &runtimeTestKey().PublicKey
}

func CreateTokenWithPayload(payload map[string]interface{}, privateKey interface{}) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(payload))
	signed, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}
	return signed
}

func CreateToken(hostUUID string, privateKey interface{}) string {
	return CreateTokenWithPayload(map[string]interface{}{"hostUuid": hostUUID}, privateKey)
}

func CreateBackendToken(reportedUUID string, privateKey interface{}) string {
	return CreateTokenWithPayload(map[string]interface{}{"reportedUuid": reportedUUID}, privateKey)
}

func GetTestConfig(addr string) *proxy.Config {
	return &proxy.Config{
		ListenAddr:   addr,
		PlatformAddr: "127.0.0.1:65535",
		PublicKey:    ParseTestPublicKey(),
	}
}

func WaitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("test proxy at %s did not become ready: %w", addr, lastErr)
}
