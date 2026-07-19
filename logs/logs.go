package logs

import (
	"bufio"
	"bytes"
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
)

type LogsHandler struct {
}

func (l *LogsHandler) Handle(key string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message) {
	defer backend.SignalHandlerClosed(key, response)

	requestUrl, err := url.Parse(initialMessage)
	if err != nil {
		log.Error("Could not parse logs request URL.")
		return
	}
	tokenString := requestUrl.Query().Get("token")
	token, valid := auth.GetAndCheckToken(tokenString)
	if !valid {
		return
	}

	logs, ok := auth.GetClaimMap(token, "logs")
	if !ok {
		log.Error("Token missing logs claim.")
		return
	}
	container, ok := auth.GetMapString(logs, "Container")
	if !ok || container == "" {
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

	client, err := events.NewDockerClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Couldn't get docker client.")
		return
	}

	reader, writer := io.Pipe()

	containerRef, err := client.InspectContainer(container)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "container": container}).Error("Couldn't inspect container for logs.")
		return
	}

	logopts := dockerClient.LogsOptions{
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
	if err := client.Logs(logopts); err != nil {
		log.WithFields(log.Fields{"error": err, "container": container}).Debug("Container log stream closed.")
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
