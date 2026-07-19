package logs

import (
	"net/http"
	// "strconv"
	"io"
	"strings"
	"testing"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"gopkg.in/check.v1"

	"github.com/PastureStack/websocket-proxy/backend"
	"github.com/PastureStack/websocket-proxy/proxy"

	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/events"
	"github.com/PastureStack/host-api/testutils"
)

var privateKey interface{}

func Test(t *testing.T) {
	check.TestingT(t)
}

type LogsTestSuite struct {
	client *docker.Client
}

var _ = check.Suite(&LogsTestSuite{})

func (s *LogsTestSuite) TestCombinedLogs(c *check.C) {
	s.doLogTest(true, "00 ", c)
}

func (s *LogsTestSuite) TestSeparatedLogs(c *check.C) {
	s.doLogTest(false, "01 ", c)
}

func (s *LogsTestSuite) doLogTest(tty bool, prefix string, c *check.C) {
	dialer := &websocket.Dialer{}
	headers := http.Header{}

	createContainerOptions := docker.CreateContainerOptions{
		Name: "logstest",
		Config: &docker.Config{
			Image:     "pasturestack/host-api-log-fixture:latest",
			OpenStdin: true,
			Tty:       tty,
		},
	}

	newCtr, err := s.client.CreateContainer(createContainerOptions)
	if err != nil {
		c.Fatalf("Error creating container, err : [%v]", err)
	}
	err = s.client.StartContainer(newCtr.ID, nil)
	if err != nil {
		c.Fatalf("Error starting container, err : [%v]", err)
	}
	defer func() {
		s.client.StopContainer(newCtr.ID, 1)
		s.client.RemoveContainer(docker.RemoveContainerOptions{
			ID:            newCtr.ID,
			RemoveVolumes: true,
			Force:         true,
		})
	}()

	payload := map[string]interface{}{
		"hostUuid": "1",
		"logs": map[string]interface{}{
			"Container": newCtr.ID,
			"Follow":    true,
		},
	}

	token := testutils.CreateTokenWithPayload(payload, privateKey)
	url := "ws://127.0.0.1:3333/v1/logs/?token=" + token
	ws, _, err := dialer.Dial(url, headers)
	if err != nil {
		c.Fatal(err)
	}
	defer ws.Close()

	for count := 0; count < 20; count++ {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if err == io.EOF || websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				return
			}
			c.Fatal(err)
		}
		msgStr := string(msg)
		if !strings.HasPrefix(msgStr, prefix) {
			c.Fatalf("Message didn't have prefix %s: [%s]", prefix, msgStr)
		}
	}
}

func (s *LogsTestSuite) setupWebsocketProxy(c *check.C) {
	config.Parse()
	config.Config.HostUuid = "1"
	config.Config.ParsedPublicKey = testutils.ParseTestPublicKey()
	privateKey = testutils.ParseTestPrivateKey()

	conf := testutils.GetTestConfig("127.0.0.1:3333")
	p := &proxy.Starter{
		BackendPaths:  []string{"/v1/connectbackend"},
		FrontendPaths: []string{"/v1/{logs:logs}/"},
		Config:        conf,
	}

	log.Infof("Starting websocket proxy. Listening on [%s], proxying to the control-platform API at [%s].",
		conf.ListenAddr, conf.PlatformAddr)

	go p.StartProxy()
	if err := testutils.WaitForTCP(conf.ListenAddr, 5*time.Second); err != nil {
		c.Fatal(err)
	}
	signedToken := testutils.CreateBackendToken("1", privateKey)

	handlers := make(map[string]backend.Handler)
	handlers["/v1/logs/"] = &LogsHandler{}
	go backend.ConnectToProxy("ws://127.0.0.1:3333/v1/connectbackend?token="+signedToken, handlers)
	if _, err := s.client.InspectImage("pasturestack/host-api-log-fixture:latest"); err != nil {
		c.Fatalf("Local log test image is missing: %v", err)
	}
}

func (s *LogsTestSuite) SetUpSuite(c *check.C) {
	cli, err := events.NewDockerClient()
	if err != nil {
		c.Fatalf("Could not connect to docker, err: [%v]", err)
	}
	s.client = cli
	s.setupWebsocketProxy(c)
}
