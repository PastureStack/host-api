package logs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/url"
	"strconv"

	dockerClient "github.com/fsouza/go-dockerclient"
	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/websocket-proxy/backend"
	"github.com/PastureStack/websocket-proxy/common"

	// "github.com/PastureStack/host-api/app/common/connect"
	"github.com/PastureStack/host-api/auth"
	"github.com/PastureStack/host-api/events"
	jwt "github.com/golang-jwt/jwt/v5"
)

type LogsHandler struct {
	dockerClient func() (*dockerClient.Client, error)
	// Optional local barrier seam; production always uses the live Engine watcher.
	streamWatch func(context.Context, string, *jwt.Token, func()) context.CancelFunc
}

func (l *LogsHandler) Handle(key string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message) {
	var audit *auth.StreamAudit
	defer func() {
		backend.SignalHandlerClosed(key, response)
		if audit != nil {
			audit.Report()
		}
	}()

	requestUrl, err := url.Parse(initialMessage)
	if err != nil {
		log.Error("Could not parse logs request URL.")
		return
	}
	tokenString := requestUrl.Query().Get("token")
	audit = auth.BeginStreamAudit(tokenString)
	token, valid := auth.GetAndCheckStreamToken(tokenString, requestUrl.Path)
	if !valid {
		return
	}
	if !audit.Ready() {
		audit.Unavailable(key, response)
		return
	}
	audit.Authorized()

	logs, ok := auth.GetClaimMap(token, "logs")
	if !ok {
		audit.Fail("HandshakeDenied")
		log.Error("Token missing logs claim.")
		return
	}
	container, ok := auth.GetMapString(logs, "Container")
	if !ok || container == "" {
		audit.Fail("HandshakeDenied")
		log.Error("Token contains an invalid logs Container claim.")
		return
	}
	follow, found := auth.GetMapBool(logs, "Follow")

	if !found {
		follow = true
	}

	tailTemp, found := auth.GetMapInt64(logs, "Lines")
	var tail string
	if found && tailTemp >= 0 && tailTemp <= 1_000_000 {
		tail = strconv.FormatInt(tailTemp, 10)
	} else {
		tail = "100"
	}

	getClient := l.dockerClient
	if getClient == nil {
		getClient = events.NewDockerClient
	}
	client, err := getClient()
	if err != nil {
		audit.Fail("DockerFailure")
		log.WithFields(log.Fields{"error": err}).Error("Couldn't get docker client.")
		return
	}

	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch := l.streamWatch
	if watch == nil {
		watch = auth.StartStreamWatch
	}
	stop := watch(ctx, tokenString, token, func() { audit.Cancel("AuthorizationRevoked"); cancel(); reader.Close(); writer.Close() })
	defer stop()

	containerRef, err := client.InspectContainer(container)
	if err != nil {
		audit.Fail("DockerFailure")
		log.WithFields(log.Fields{"error": err, "container": container}).Error("Couldn't inspect container for logs.")
		return
	}

	logopts := dockerClient.LogsOptions{
		Context:    ctx,
		Container:  container,
		Follow:     follow,
		Stdout:     true,
		Stderr:     true,
		Timestamps: true,
		Tail:       tail,
	}
	if containerRef.Config.Tty {
		logopts.OutputStream = stdbothWriter{writer}
		logopts.RawTerminal = true
	} else {
		logopts.OutputStream = stdoutWriter{writer}
		logopts.ErrorStream = stderrorWriter{writer}
		logopts.RawTerminal = false
	}

	go func(w *io.PipeWriter) {
		for {
			_, ok := <-incomingMessages
			if !ok {
				audit.Cancel("ClientDisconnected")
				cancel()
				w.Close()
				return
			}
		}
	}(writer)

	go func(r *io.PipeReader) {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		scanner.Split(customSplit)
		for scanner.Scan() {
			text := scanner.Text()
			message := common.Message{
				Key:  key,
				Type: common.Body,
				Body: text,
			}
			response <- message
		}
		if err := scanner.Err(); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Error with the container log scanner.")
		}
	}(reader)

	// Returns an error, but ignoring it because it will always return an error when a streaming call is made.
	if err := client.Logs(logopts); err != nil && !errors.Is(err, io.EOF) {
		audit.Fail("DockerFailure")
		log.WithFields(log.Fields{"error": err, "container": container}).Debug("Container log stream closed.")
	} else {
		audit.Succeed()
	}
}

func customSplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	if i := bytes.Index(data, messageSeparator); i >= 0 {
		return i + messageSeparatorLength, data[0:i], nil
	}

	if atEOF {
		return len(data), data, nil
	}

	return 0, nil, nil
}
