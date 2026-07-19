package dockersocketproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"testing"
	"time"

	"github.com/fsouza/go-dockerclient"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"gopkg.in/check.v1"

	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/events"
	"github.com/PastureStack/host-api/testutils"
	"github.com/PastureStack/websocket-proxy/backend"
	"github.com/PastureStack/websocket-proxy/proxy"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type ProxyTestSuite struct {
	client     *docker.Client
	privateKey interface{}
}

var _ = check.Suite(&ProxyTestSuite{})

const (
	testImageRepo = "busybox"
	testImageTag  = "1"
	testImage     = testImageRepo + ":" + testImageTag
)

func (s *ProxyTestSuite) TestSimpleCalls(c *check.C) {
	ws := s.connect(c)
	defer ws.Close()

	encoded := encodeRequest("GET", "/_ping", nil, c)
	ws.WriteMessage(websocket.TextMessage, encoded)
	checkResponse(map[string]string{"HTTP/1.1 200 OK": "", "OK": ""}, ws, c)

	encoded = encodeRequest("GET", "/version", nil, c)
	ws.WriteMessage(websocket.TextMessage, encoded)
	checkResponse(map[string]string{"HTTP/1.1 200 OK": "", "ApiVersion": ""}, ws, c)
}

func (s *ProxyTestSuite) TestRejectsTokenWithoutDockerSocketScope(c *check.C) {
	dialer := &websocket.Dialer{}
	token := testutils.CreateTokenWithPayload(map[string]interface{}{
		"hostUuid": "1",
		"scope":    "logs",
	}, s.privateKey)
	ws, _, err := dialer.Dial("ws://127.0.0.1:4444/v1/dockersocket/?token="+token, nil)
	if err != nil {
		c.Fatal(err)
	}
	defer ws.Close()
	if err := ws.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		c.Fatal(err)
	}
	if _, _, err := ws.ReadMessage(); err == nil {
		c.Fatal("Docker socket connection remained open without the required scope")
	}
}

func (s *ProxyTestSuite) TestStartAndConnect(c *check.C) {
	ws := s.connect(c)
	defer ws.Close()

	createConfig := &docker.Config{
		Image:     testImage,
		Tty:       true,
		OpenStdin: true,
		Cmd:       []string{"sh", "-c", "echo Sleeping 1; echo Sleeping 3; sleep 5"},
	}

	container := s.createAndStart(ws, createConfig, c)

	encoded := encodeRequest("POST", fmt.Sprintf("/containers/%s/attach?logs=1&stream=1&stdout=1", container.ID), nil, c)
	ws.WriteMessage(websocket.TextMessage, encoded)
	checkResponse(map[string]string{"Content-Type: application/vnd.docker.raw-stream": "", "Sleeping 1": "", "Sleeping 3": ""}, ws, c)
}

func (s *ProxyTestSuite) TestInteractive(c *check.C) {
	ws := s.connect(c)
	defer ws.Close()

	createConfig := &docker.Config{
		Image:     testImage,
		Tty:       true,
		OpenStdin: true,
		Cmd:       []string{"sh"},
	}

	container := s.createAndStart(ws, createConfig, c)

	encoded := encodeRequest("POST", fmt.Sprintf("/containers/%s/attach?stream=1&stdout=1&stdin=1&stderr=1", container.ID), nil, c)
	ws.WriteMessage(websocket.TextMessage, encoded)
	checkResponse(map[string]string{"Content-Type: application/vnd.docker.raw-stream": ""}, ws, c)

	encoded = encodeMessage("touch foo\n")
	ws.WriteMessage(websocket.TextMessage, encoded)
	encoded = encodeMessage("ls\n")
	ws.WriteMessage(websocket.TextMessage, encoded)
	checkResponse(map[string]string{"bin": "", "foo": ""}, ws, c)
}

/*
func (s *ProxyTestSuite) TestToCompareDockerClientBehavior(c *check.C) {

	// var reader bytes.Buffer
	// var writer bytes.Buffer
	inputReader, inputWriter := io.Pipe()
	reader, writer := io.Pipe()
	opts := docker.AttachToContainerOptions{
		RawTerminal:  true,
		Stdin:        true,
		Stdout:       true,
		Stderr:       true,
		Stream:       true,
		InputStream:  inputReader,
		OutputStream: writer,
		ErrorStream:  writer,
		Container:    "id goes here",
	}
	go s.client.AttachToContainer(opts)
	go func() {
		for {
			buff := make([]byte, 32)
			n, err := reader.Read(buff[:])
			if n > 0 {
				log.Info("I GOT THIS MSG: ", string(buff))
			}
			if err != nil {
				if err != io.EOF {
					c.Fatal(err)
				}
				return
			}
		}
	}()
	inputWriter.Write([]byte("ls\n"))
	time.Sleep(time.Second * 3)
}
*/

func (s *ProxyTestSuite) createAndStart(ws *websocket.Conn, createConfig *docker.Config, c *check.C) *docker.Container {
	body, err := json.Marshal(createConfig)
	if err != nil {
		c.Fatalf("Failed to marshal json. %#v", err)
	}
	encoded := encodeRequest("POST", "/containers/create", body, c)
	ws.WriteMessage(websocket.TextMessage, encoded)
	respMsg := checkResponse(map[string]string{"HTTP/1.1 201 Created": ""}, ws, c)
	container := &docker.Container{}
	found := false
	for _, line := range strings.Split(respMsg, "\n") {
		if strings.HasPrefix(line, "{") {
			json.Unmarshal([]byte(line), container)
			found = true
		}
	}
	if !found {
		c.Fatal("Didn't find body!")
	}
	encoded = encodeRequest("POST", fmt.Sprintf("/containers/%s/start", container.ID), nil, c)
	ws.WriteMessage(websocket.TextMessage, encoded)
	respMsg = checkResponse(map[string]string{"HTTP/1.1 204 No Content": ""}, ws, c)
	return container
}

func (s *ProxyTestSuite) connect(c *check.C) *websocket.Conn {
	dialer := &websocket.Dialer{}
	headers := http.Header{}
	payload := map[string]interface{}{
		"hostUuid": "1",
		"scope":    "dockersocket",
	}
	token := testutils.CreateTokenWithPayload(payload, s.privateKey)
	url := "ws://127.0.0.1:4444/v1/dockersocket/?token=" + token
	ws, _, err := dialer.Dial(url, headers)
	if err != nil {
		c.Fatal(err)
	}
	return ws
}

func checkResponse(checkFor map[string]string, ws *websocket.Conn, c *check.C) string {
	lastMsg := ""
	for count := 0; count < 20; count++ {
		if err := ws.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			c.Fatal(err)
		}
		_, m, err := ws.ReadMessage()
		if err != nil {
			// ws closed
			if len(checkFor) != 0 {
				c.Fatalf("Didn't find all keys before ws was closed: %v. Last message: %s. Error: %v", checkFor, lastMsg, err)
			}
			return ""
		}
		dst := make([]byte, base64.StdEncoding.DecodedLen(len(m)))
		n, err := base64.StdEncoding.Decode(dst, m)
		if err != nil {
			c.Fatal(err)
		}
		msg := string(dst[:n])
		lastMsg = msg
		for k := range checkFor {
			if strings.Contains(msg, k) {
				delete(checkFor, k)
			}
		}
		if len(checkFor) == 0 {
			return msg
		}
	}

	if len(checkFor) != 0 {
		c.Fatalf("Didn't find: %v. Last message: %s", checkFor, lastMsg)
	}

	return ""
}

func encodeMessage(msg string) []byte {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(msg)))
	base64.StdEncoding.Encode(encoded, []byte(msg))
	return encoded
}

func encodeRequest(method string, uri string, body []byte, c *check.C) []byte {
	reader := bytes.NewReader(body)
	req, err := http.NewRequest(method, "http://foo"+uri, reader)
	if err != nil {
		c.Fatalf("Failed creating new request. %#v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		c.Fatalf("Failed dumping request. %#v", err)
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(dump)))
	base64.StdEncoding.Encode(encoded, dump)
	return encoded
}

func (s *ProxyTestSuite) setupWebsocketProxy(c *check.C) {
	// TODO Deduplicate. This method and the two below are close copies of the ones in logs_test.go.
	config.Parse()
	config.Config.HostUuid = "1"
	config.Config.ParsedPublicKey = testutils.ParseTestPublicKey()
	s.privateKey = testutils.ParseTestPrivateKey()

	conf := testutils.GetTestConfig("127.0.0.1:4444")
	p := &proxy.Starter{
		BackendPaths:  []string{"/v1/connectbackend"},
		FrontendPaths: []string{"/v1/{dockersocket:dockersocket}/"},
		Config:        conf,
	}

	log.Infof("Starting websocket proxy. Listening on [%s].", conf.ListenAddr)

	go p.StartProxy()
	if err := testutils.WaitForTCP(conf.ListenAddr, 5*time.Second); err != nil {
		c.Fatal(err)
	}
	signedToken := testutils.CreateBackendToken("1", s.privateKey)

	handlers := make(map[string]backend.Handler)
	handlers["/v1/dockersocket/"] = &Handler{}
	go backend.ConnectToProxy("ws://127.0.0.1:4444/v1/connectbackend?token="+signedToken, handlers)
	if _, err := s.client.InspectImage(testImage); err != nil {
		c.Fatalf("Local Docker socket proxy test image is missing: %v", err)
	}
}

func (s *ProxyTestSuite) SetUpSuite(c *check.C) {
	cli, err := events.NewDockerClient()
	if err != nil {
		c.Fatalf("Could not connect to docker, err: [%v]", err)
	}
	s.client = cli
	s.setupWebsocketProxy(c)
}
