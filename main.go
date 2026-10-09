package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PastureStack/host-api/auth"
	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/console"
	"github.com/PastureStack/host-api/dockersocketproxy"
	"github.com/PastureStack/host-api/events"
	"github.com/PastureStack/host-api/exec"
	"github.com/PastureStack/host-api/logs"
	"github.com/PastureStack/host-api/platformapi"
	"github.com/PastureStack/host-api/proxy"
	"github.com/PastureStack/host-api/stats"
	"github.com/PastureStack/host-api/util"
	"github.com/sirupsen/logrus"

	"github.com/golang/glog"

	"github.com/PastureStack/websocket-proxy/backend"
)

var (
	version     = "0.38.5"
	showVersion = flag.Bool("version", false, "Print the host API version and exit")
)

func main() {
	err := config.Parse()
	if err != nil {
		logrus.Fatal(err)
	}
	if *showVersion {
		fmt.Println(version)
		return
	}
	stopCompletionReplay := auth.StartCompletionReplay(context.Background())
	defer stopCompletionReplay()

	defer glog.Flush()

	if config.Config.PidFile != "" {
		logrus.Infof("Writing pid %d to %s", os.Getpid(), config.Config.PidFile)
		if err := os.WriteFile(config.Config.PidFile, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
			logrus.Fatalf("Failed to write pid file %s: %v", config.Config.PidFile, err)
		}
	}

	if config.Config.LogFile != "" {
		if output, err := os.OpenFile(config.Config.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666); err != nil {
			logrus.Fatalf("Failed to log to file %s: %v", config.Config.LogFile, err)
		} else {
			logrus.SetOutput(output)
		}
	}

	processor := events.NewDockerEventsProcessor(config.Config.EventsPoolSize)
	err = processor.Process()
	if err != nil {
		logrus.Fatal(err)
	}

	platformClient, err := util.GetPlatformClient()
	if err != nil {
		logrus.Fatal(err)
	}

	tokenRequest := &platformapi.HostAPIProxyToken{
		ReportedUUID: config.Config.HostUuid,
	}
	tokenResponse, err := getConnectionToken(0, tokenRequest, platformClient)
	if err != nil {
		logrus.Fatal(err)
	} else if tokenResponse == nil {
		// nil error and blank token means the proxy is turned off. Just block forever so main function doesn't exit
		var block chan bool
		<-block
	}

	handlers := make(map[string]backend.Handler)
	logrus.Info(operatorMessage(config.Config.Locale, "start"))
	handlers["/v1/logs/"] = &logs.LogsHandler{}
	handlers["/v2-beta/logs/"] = &logs.LogsHandler{}
	handlers["/v1/stats/"] = &stats.StatsHandler{}
	handlers["/v2-beta/stats/"] = &stats.StatsHandler{}
	handlers["/v1/hoststats/"] = &stats.HostStatsHandler{}
	handlers["/v2-beta/hoststats/"] = &stats.HostStatsHandler{}
	handlers["/v1/containerstats/"] = &stats.ContainerStatsHandler{}
	handlers["/v2-beta/containerstats/"] = &stats.ContainerStatsHandler{}
	handlers["/v1/exec/"] = &exec.ExecHandler{}
	handlers["/v2-beta/exec/"] = &exec.ExecHandler{}
	handlers["/v1/console/"] = &console.Handler{}
	handlers["/v2-beta/console/"] = &console.Handler{}
	handlers["/v1/dockersocket/"] = &dockersocketproxy.Handler{}
	handlers["/v2-beta/dockersocket/"] = &dockersocketproxy.Handler{}
	handlers["/v1/container-proxy/"] = &proxy.Handler{}
	handlers["/v2-beta/container-proxy/"] = &proxy.Handler{}
	connectionURL, err := proxyConnectionURL(tokenResponse)
	if err != nil {
		logrus.Fatal(err)
	}
	if err := backend.ConnectToProxy(connectionURL, handlers); err != nil {
		logrus.Fatal(err)
	}
}

const maxProxyTokenBytes = 16 << 10

func proxyConnectionURL(tokenResponse *platformapi.HostAPIProxyToken) (string, error) {
	if tokenResponse == nil {
		return "", fmt.Errorf("host API proxy token response is missing")
	}
	if tokenResponse.Token == "" || len(tokenResponse.Token) > maxProxyTokenBytes {
		return "", fmt.Errorf("host API proxy token must contain between 1 and %d bytes", maxProxyTokenBytes)
	}
	endpoint, err := url.Parse(tokenResponse.URL)
	if err != nil {
		return "", fmt.Errorf("invalid host API proxy URL: %w", err)
	}
	if endpoint.Scheme != "ws" && endpoint.Scheme != "wss" {
		return "", fmt.Errorf("host API proxy URL must use ws or wss")
	}
	if endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return "", fmt.Errorf("host API proxy URL has an invalid authority or fragment")
	}
	query := endpoint.Query()
	query.Set("token", tokenResponse.Token)
	query.Set("hostApiVersion", version)
	query.Set("hostApiCapabilities", "key-audit-v1,key-delegation-v1")
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

const maxWaitOnHostTries = 20

func getConnectionToken(try int, tokenReq *platformapi.HostAPIProxyToken, platformClient *platformapi.Client) (*platformapi.HostAPIProxyToken, error) {
	if platformClient == nil || platformClient.HostAPIProxyToken == nil {
		return nil, nil
	}
	for attempt := try; attempt < maxWaitOnHostTries; attempt++ {
		tokenResponse, err := platformClient.HostAPIProxyToken.Create(tokenReq)
		if err == nil {
			return tokenResponse, nil
		}
		apiError, ok := err.(*platformapi.APIError)
		if !ok {
			return nil, err
		}
		if apiError.StatusCode == 501 {
			logrus.Info("Host API proxy disabled. Will not connect.")
			return nil, nil
		}
		if apiError.StatusCode != 422 {
			return nil, err
		}
		parsed := &ParsedError{}
		if unmarshalErr := json.Unmarshal([]byte(apiError.Body), parsed); unmarshalErr != nil {
			return nil, unmarshalErr
		}
		if !strings.EqualFold(parsed.Code, "InvalidReference") || !strings.EqualFold(parsed.FieldName, "reportedUuid") {
			return nil, err
		}
		logrus.WithField("reportedUuid", config.Config.HostUuid).WithField("attempt", attempt+1).Info("Host is not registered yet; retrying in one second.")
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("reached %d attempts while waiting for host registration", maxWaitOnHostTries)
}

func operatorMessage(locale, key string) string {
	messages := map[string]map[string]string{
		"en-US": {"start": "PastureStack host API is ready to connect"},
		"zh-TW": {"start": "PastureStack 主機 API 已準備連線"},
	}
	return messages[locale][key]
}

type ParsedError struct {
	Code      string
	FieldName string
}
