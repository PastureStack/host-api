package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationPrecedenceAndLegacyAliases(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "host-api.ini")
	if err := os.WriteFile(filename, []byte("port = 8181\nlocale = en-US\ncattle-url = http://legacy.example.test/v2-beta\n"), 0600); err != nil {
		t.Fatal(err)
	}
	environment := map[string]string{
		"HOST_API_CONFIG_FILE": filename,
		"HOST_API_PORT":        "8282",
		"HOST_API_LOCALE":      "zh-TW",
	}
	lookup := func(key string) (string, bool) {
		value, ok := environment[key]
		return value, ok
	}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	candidate, err := parse(set, []string{"-port=8383"}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	Config = candidate
	if err := finalize(); err != nil {
		t.Fatal(err)
	}
	if Config.Port != 8383 || Config.Locale != "zh-TW" {
		t.Fatalf("unexpected precedence result: %#v", Config)
	}
	if Config.PlatformURL != "http://legacy.example.test/v2-beta" {
		t.Fatalf("legacy URL alias was not preserved: %q", Config.PlatformURL)
	}
}

func TestConfigurationRejectsInvalidValues(t *testing.T) {
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	candidate, err := parse(set, []string{"-locale=zh-CN"}, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	Config = candidate
	if err := finalize(); err == nil {
		t.Fatal("invalid locale was accepted")
	}
}

func TestParsedPublicKeyRejectsMalformedPEM(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(filename, []byte("not a PEM key"), 0600); err != nil {
		t.Fatal(err)
	}
	Config = defaults()
	Config.Key = filename
	if err := ParsedPublicKey(); err == nil {
		t.Fatal("malformed PEM was accepted")
	}
}

func TestParsedPublicKeyAcceptsRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(filename, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	Config = defaults()
	Config.Key = filename
	if err := ParsedPublicKey(); err != nil {
		t.Fatal(err)
	}
	if _, ok := Config.ParsedPublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("unexpected public key type %T", Config.ParsedPublicKey)
	}
}

func TestParsedPublicKeyRejectsWeakRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(filename, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	Config = defaults()
	Config.Key = filename
	if err := ParsedPublicKey(); err == nil {
		t.Fatal("weak RSA public key was accepted")
	}
}

func TestParsedPublicKeyRejectsOversizedFile(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "public.pem")
	contents := make([]byte, maxConfigFileBytes+1)
	if err := os.WriteFile(filename, contents, 0600); err != nil {
		t.Fatal(err)
	}
	Config = defaults()
	Config.Key = filename
	if err := ParsedPublicKey(); err == nil {
		t.Fatal("oversized public key file was accepted")
	}
}
