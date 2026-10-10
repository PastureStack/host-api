package config

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/golang/glog"
)

const (
	maxConfigFileBytes = 1 << 20
	minimumRSAKeyBits  = 2048
)

type config struct {
	CAdvisorUrl           string
	DockerUrl             string
	Systemd               bool
	NumStats              int
	Auth                  bool
	HaProxyMonitor        bool
	Key                   string
	HostUuid              string
	Port                  int
	Ip                    string
	ParsedPublicKey       interface{}
	HostUuidCheck         bool
	EventsPoolSize        int
	PlatformURL           string
	PlatformAccessKey     string
	PlatformSecretKey     string
	LegacyCattleURL       string
	LegacyCattleAccessKey string
	LegacyCattleSecretKey string
	Locale                string
	PidFile               string
	LogFile               string
	CompletionSpoolDir    string
}

var Config config

func defaults() config {
	return config{
		CAdvisorUrl:    "http://localhost:8081",
		DockerUrl:      "unix:///var/run/docker.sock",
		NumStats:       600,
		Port:           8080,
		HostUuidCheck:  true,
		EventsPoolSize: 10,
		Locale:         "en-US",
	}
}

func ParsedPublicKey() error {
	keyBytes, err := readBoundedFile(Config.Key, maxConfigFileBytes)
	if err != nil {
		glog.Error("Error reading public key file")
		return err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return errors.New("public key file does not contain a PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key must be RSA, got %T", parsed)
	}
	if publicKey.N == nil || publicKey.N.BitLen() < minimumRSAKeyBits {
		return fmt.Errorf("RSA public key must be at least %d bits", minimumRSAKeyBits)
	}

	Config.ParsedPublicKey = publicKey
	return nil
}

func readBoundedFile(filename string, maximum int64) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return contents, nil
}

func Parse() error {
	candidate, err := parse(flag.CommandLine, os.Args[1:], os.LookupEnv)
	if err != nil {
		return err
	}
	Config = candidate
	return finalize()
}

func parse(set *flag.FlagSet, args []string, lookupEnv func(string) (string, bool)) (config, error) {
	candidate := defaults()
	registerFlags(set, &candidate)
	if err := set.Parse(args); err != nil {
		return config{}, err
	}

	visited := make(map[string]bool)
	set.Visit(func(item *flag.Flag) {
		visited[item.Name] = true
	})

	values := map[string]string{}
	if filename, ok := lookupEnv("HOST_API_CONFIG_FILE"); ok && filename != "" {
		fileValues, err := readConfigFile(filename)
		if err != nil {
			return config{}, err
		}
		values = fileValues
	}

	var applyErr error
	set.VisitAll(func(item *flag.Flag) {
		if applyErr != nil || visited[item.Name] || !isConfigFlag(item.Name) {
			return
		}
		environmentName := "HOST_API_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(item.Name))
		if value, ok := lookupEnv(environmentName); ok && value != "" {
			applyErr = set.Set(item.Name, value)
			return
		}
		if item.Name == "locale" {
			if value, ok := lookupEnv("PASTURESTACK_LOCALE"); ok && value != "" {
				applyErr = set.Set(item.Name, value)
				return
			}
		}
		if value, ok := values[item.Name]; ok {
			applyErr = set.Set(item.Name, value)
		}
	})
	if applyErr != nil {
		return config{}, applyErr
	}

	return candidate, nil
}

func registerFlags(set *flag.FlagSet, target *config) {
	set.BoolVar(&target.HaProxyMonitor, "haproxy-monitor", target.HaProxyMonitor, "Monitor HAProxy")
	set.IntVar(&target.Port, "port", target.Port, "Listen port")
	set.StringVar(&target.Ip, "ip", target.Ip, "Listen IP, defaults to all IPs")
	set.StringVar(&target.CAdvisorUrl, "cadvisor-url", target.CAdvisorUrl, "cAdvisor URL")
	set.StringVar(&target.DockerUrl, "docker-host", target.DockerUrl, "Docker host URL")
	set.IntVar(&target.NumStats, "num-stats", target.NumStats, "Number of stats to show by default")
	set.BoolVar(&target.Auth, "auth", target.Auth, "Authenticate requests")
	set.StringVar(&target.HostUuid, "host-uuid", target.HostUuid, "Host UUID")
	set.BoolVar(&target.HostUuidCheck, "host-uuid-check", target.HostUuidCheck, "Validate host UUID")
	set.StringVar(&target.Key, "public-key", target.Key, "Public Key for Authentication")
	set.IntVar(&target.EventsPoolSize, "events-pool-size", target.EventsPoolSize, "Size of worker pool for processing Docker events")
	set.StringVar(&target.PlatformURL, "platform-url", target.PlatformURL, "Control-platform API URL")
	set.StringVar(&target.PlatformAccessKey, "platform-access-key", target.PlatformAccessKey, "Control-platform API access key")
	set.StringVar(&target.PlatformSecretKey, "platform-secret-key", target.PlatformSecretKey, "Control-platform API secret key")
	set.StringVar(&target.LegacyCattleURL, "cattle-url", target.LegacyCattleURL, "Legacy control-platform API URL alias")
	set.StringVar(&target.LegacyCattleAccessKey, "cattle-access-key", target.LegacyCattleAccessKey, "Legacy API access-key alias")
	set.StringVar(&target.LegacyCattleSecretKey, "cattle-secret-key", target.LegacyCattleSecretKey, "Legacy API secret-key alias")
	set.StringVar(&target.Locale, "locale", target.Locale, "Operator message locale: en-US or zh-TW")
	set.StringVar(&target.PidFile, "pid-file", target.PidFile, "PID file")
	set.StringVar(&target.LogFile, "log", target.LogFile, "Log file")
	set.StringVar(&target.CompletionSpoolDir, "completion-spool-dir", target.CompletionSpoolDir, "Private persistent API Key terminal-evidence spool directory")
}

func isConfigFlag(name string) bool {
	switch name {
	case "haproxy-monitor", "port", "ip", "cadvisor-url", "docker-host", "num-stats", "auth",
		"host-uuid", "host-uuid-check", "public-key", "events-pool-size", "platform-url",
		"platform-access-key", "platform-secret-key", "cattle-url", "cattle-access-key",
		"cattle-secret-key", "locale", "pid-file", "log", "completion-spool-dir":
		return true
	default:
		return false
	}
}

func finalize() error {
	if Config.PlatformURL == "" {
		Config.PlatformURL = Config.LegacyCattleURL
	}
	if Config.PlatformAccessKey == "" {
		Config.PlatformAccessKey = Config.LegacyCattleAccessKey
	}
	if Config.PlatformSecretKey == "" {
		Config.PlatformSecretKey = Config.LegacyCattleSecretKey
	}
	if Config.Locale != "en-US" && Config.Locale != "zh-TW" {
		return fmt.Errorf("unsupported locale %q; use en-US or zh-TW", Config.Locale)
	}
	if Config.Port < 1 || Config.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if Config.EventsPoolSize < 1 {
		return fmt.Errorf("events-pool-size must be positive")
	}
	if Config.NumStats < 1 {
		return fmt.Errorf("num-stats must be positive")
	}

	if Config.Key != "" {
		if err := ParsedPublicKey(); err != nil {
			return err
		}
	}

	info, err := os.Stat("/run/systemd/system")
	Config.Systemd = err == nil && info.IsDir()
	return nil
}

func readConfigFile(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	limited := &io.LimitedReader{R: file, N: maxConfigFileBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64*1024), maxConfigFileBytes)
	values := make(map[string]string)
	rootSection := true
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("invalid section header on line %d", lineNumber)
			}
			rootSection = strings.TrimSpace(line[1:len(line)-1]) == ""
			continue
		}
		if !rootSection {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("invalid configuration on line %d", lineNumber)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			return nil, fmt.Errorf("empty configuration key on line %d", lineNumber)
		}
		key = strings.ReplaceAll(key, "_", "-")
		if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		} else if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			unquoted, err := strconv.Unquote(value)
			if err != nil {
				return nil, fmt.Errorf("invalid quoted value on line %d: %w", lineNumber, err)
			}
			value = unquoted
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("configuration file exceeds %d bytes", maxConfigFileBytes)
	}
	return values, nil
}
