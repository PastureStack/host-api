package stats

import (
	"flag"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	client "github.com/fsouza/go-dockerclient"

	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/testutils"
	"github.com/PastureStack/websocket-proxy/backend"
	"github.com/PastureStack/websocket-proxy/proxy"
)

var privateKey interface{}

func TestContainerStats(t *testing.T) {
	dialer := &websocket.Dialer{}
	headers := http.Header{}
	c, err := client.NewClient("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatalf("Could not connect to docker, err: [%v]", err)
	}
	allCtrs, err := c.ListContainers(client.ListContainersOptions{})
	if err != nil {
		t.Fatalf("Error listing all images, err : [%v]", err)
	}
	ctrs := []client.APIContainers{}
	for _, ctr := range allCtrs {
		if strings.HasPrefix(ctr.Image, "busybox:1") && hasNamePrefix(ctr.Names, "/pasturestack-host-api-test-") {
			ctrs = append(ctrs, ctr)
		}
	}
	if len(ctrs) != 1 {
		t.Fatalf("Expected 1 containers, but got %v: [%v]", len(ctrs), ctrs)
	}

	cIds := map[string]string{}
	payload := map[string]interface{}{
		"hostUuid":     "1",
		"containerIds": cIds,
	}

	for i, ctr := range ctrs {
		cIds[ctr.ID] = "1i" + strconv.Itoa(i+1)
	}

	log.Infof("%+v", cIds)
	time.Sleep(2 * time.Second)

Outer:
	for i := 0; i < 5; i++ {
		token := testutils.CreateTokenWithPayload(payload, privateKey)
		url := "ws://127.0.0.1:1111/v1/containerstats?token=" + token
		ws, _, err := dialer.Dial(url, headers)
		if err != nil {
			t.Fatal(err)
		}
		defer ws.Close()

		for count := 0; count < 4; count++ {
			_, msg, err := ws.ReadMessage()
			if err == io.EOF {
				// May take a second or two before cadvisor knows about the container
				time.Sleep(500 * time.Millisecond)
				continue Outer
			}
			if err != nil {
				t.Fatal(err)
			}
			stats := string(msg)
			if !strings.Contains(stats, "1i1") {
				t.Fatalf("Stats are not working. Output: [%s]", stats)
			}
		}
		return
	}

	log.Fatal(io.EOF)
}

func hasNamePrefix(names []string, prefix string) bool {
	for _, name := range names {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// This test wont work in dind. Disabling it for now, until I figure out a solution
func unTestContainerStatSingleContainer(t *testing.T) {
	dialer := &websocket.Dialer{}
	headers := http.Header{}

	c, err := client.NewClient("unix:///var/run/docker.sock")
	if err != nil {
		t.Fatalf("Could not connect to docker, err: [%v]", err)
	}

	ctrs, err := c.ListContainers(client.ListContainersOptions{
		Filters: map[string][]string{
			"image": {"google/cadvisor"},
		},
	})
	if err != nil || len(ctrs) == 0 {
		t.Fatalf("Error listing all images, err : [%v]", err)
	}
	payload := map[string]interface{}{
		"hostUuid": "1",
		"containerIds": map[string]string{
			ctrs[0].ID: "1i1",
		},
	}

	log.Info(ctrs[0].ID)

	token := testutils.CreateTokenWithPayload(payload, privateKey)
	url := "ws://127.0.0.1:1111/v1/containerstats/" + ctrs[0].ID + "?token=" + token
	ws, _, err := dialer.Dial(url, headers)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	for count := 0; count < 4; count++ {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		stats := string(msg)
		if !strings.Contains(stats, "1i1") {
			t.Fatalf("Stats are not working. Output: [%s]", stats)
		}
	}
}

func TestHostStats(t *testing.T) {
	dialer := &websocket.Dialer{}
	headers := http.Header{}

	payload := map[string]interface{}{
		"hostUuid":   "1",
		"resourceId": "1h1",
	}

	token := testutils.CreateTokenWithPayload(payload, privateKey)
	url := "ws://127.0.0.1:1111/v1/hoststats?token=" + token
	ws, _, err := dialer.Dial(url, headers)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	for count := 0; count < 4; count++ {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		stats := string(msg)
		if !strings.Contains(stats, "1h1") {
			t.Fatalf("Stats are not working. Output: [%s]", stats)
		}
	}
}

func TestHostStatsLegacy(t *testing.T) {
	dialer := &websocket.Dialer{}
	headers := http.Header{}
	token := testutils.CreateTokenWithPayload(map[string]interface{}{
		"hostUuid":   "1",
		"resourceId": "1h1",
	}, privateKey)
	url := "ws://127.0.0.1:1111/v1/stats?token=" + token
	ws, _, err := dialer.Dial(url, headers)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	count := 0
	for {
		if count > 3 {
			break
		}

		_, msg, err := ws.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		stats := string(msg)
		if !strings.Contains(stats, "cpu") {
			t.Fatalf("Stats are not working. Output: [%s]", stats)
		}
		count++
	}
}

func setupWebsocketProxy() error {
	config.Parse()
	config.Config.NumStats = 1
	config.Config.HostUuid = "1"
	config.Config.CAdvisorUrl = "http://localhost:8080"
	config.Config.ParsedPublicKey = testutils.ParseTestPublicKey()
	privateKey = testutils.ParseTestPrivateKey()

	conf := testutils.GetTestConfig("127.0.0.1:1111")
	p := &proxy.Starter{
		BackendPaths:  []string{"/v1/connectbackend"},
		FrontendPaths: []string{"/v1/{logs:logs}/", "/v1/{stats:stats}", "/v1/{stats:stats}/{statsid}", "/v1/exec/"},
		StatsPaths: []string{"/v1/{hoststats:hoststats(?:\\/project)?(?:\\/)?}",
			"/v1/{containerstats:containerstats(?:\\/service)?(?:\\/)?}",
			"/v1/{containerstats:containerstats}/{containerid}"},
		Config: conf,
	}

	log.Infof("Starting websocket proxy. Listening on [%s], proxying to the control-platform API at [%s].",
		conf.ListenAddr, conf.PlatformAddr)

	go p.StartProxy()
	if err := testutils.WaitForTCP(conf.ListenAddr, 5*time.Second); err != nil {
		return err
	}
	signedToken := testutils.CreateBackendToken("1", privateKey)

	handlers := make(map[string]backend.Handler)
	handlers["/v1/stats/"] = &StatsHandler{}
	handlers["/v1/hoststats/"] = &HostStatsHandler{}
	handlers["/v1/containerstats/"] = &ContainerStatsHandler{}
	go backend.ConnectToProxy("ws://127.0.0.1:1111/v1/connectbackend?token="+signedToken, handlers)
	time.Sleep(300 * time.Millisecond)
	return nil
}

func TestMain(m *testing.M) {
	flag.Parse()
	if err := setupWebsocketProxy(); err != nil {
		log.Errorf("Could not start the stats test proxy: %v", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
