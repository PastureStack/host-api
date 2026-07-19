package exec

import (
	"encoding/base64"
	"io"
	"net/url"

	dockerClient "github.com/fsouza/go-dockerclient"
	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/websocket-proxy/backend"
	"github.com/PastureStack/websocket-proxy/common"

	"github.com/PastureStack/host-api/auth"
	"github.com/PastureStack/host-api/events"
)

type ExecHandler struct {
}

func (h *ExecHandler) Handle(key string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message) {
	defer backend.SignalHandlerClosed(key, response)

	requestUrl, err := url.Parse(initialMessage)
	if err != nil {
		log.Error("Could not parse exec request URL.")
		return
	}
	tokenString := requestUrl.Query().Get("token")
	token, valid := auth.GetAndCheckToken(tokenString)
	if !valid {
		return
	}

	execMap, ok := auth.GetClaimMap(token, "exec")
	if !ok {
		log.Error("Token missing exec claim.")
		return
	}
	execConfig := convert(execMap)
	if execConfig.Container == "" || len(execConfig.Cmd) == 0 {
		log.Error("Token contains an invalid exec configuration.")
		return
	}

	client, err := events.NewDockerClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Couldn't get docker client.")
		return
	}

	outputReader, outputWriter := io.Pipe()
	inputReader, inputWriter := io.Pipe()
	defer outputReader.Close()
	defer outputWriter.Close()
	defer inputReader.Close()
	defer inputWriter.Close()

	execObj, err := client.CreateExec(execConfig)
	if err != nil {
		return
	}

	go func() {
		for {
			msg, ok := <-incomingMessages
			if !ok {
				if _, err := inputWriter.Write([]byte("\x04")); err != nil {
					log.WithFields(log.Fields{"error": err}).Debug("Exec input stream was already closed.")
				}
				inputWriter.Close()
				return
			}
			data, err := base64.StdEncoding.DecodeString(msg)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Error decoding message.")
				continue
			}
			if _, err := inputWriter.Write(data); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Error writing exec input.")
				return
			}
		}
	}()

	go func(r *io.PipeReader) {
		buffer := make([]byte, 4096, 4096)
		for {
			c, err := r.Read(buffer)
			if c > 0 {
				text := base64.StdEncoding.EncodeToString(buffer[:c])
				message := common.Message{
					Key:  key,
					Type: common.Body,
					Body: text,
				}
				response <- message
			}
			if err != nil {
				break
			}
		}
	}(outputReader)

	startConfig := dockerClient.StartExecOptions{
		Detach:       false,
		Tty:          true,
		RawTerminal:  true,
		InputStream:  inputReader,
		OutputStream: outputWriter,
	}

	if err := client.StartExec(execObj.ID, startConfig); err != nil {
		log.WithFields(log.Fields{"error": err, "exec": execObj.ID}).Error("Exec session failed.")
	}
}

func convert(execMap map[string]interface{}) dockerClient.CreateExecOptions {
	// Not fancy at all
	config := dockerClient.CreateExecOptions{}

	if param, ok := execMap["AttachStdin"]; ok {
		if val, ok := param.(bool); ok {
			config.AttachStdin = val
		}
	}

	if param, ok := execMap["AttachStdout"]; ok {
		if val, ok := param.(bool); ok {
			config.AttachStdout = val
		}
	}

	if param, ok := execMap["AttachStderr"]; ok {
		if val, ok := param.(bool); ok {
			config.AttachStderr = val
		}
	}

	if param, ok := execMap["Tty"]; ok {
		if val, ok := param.(bool); ok {
			config.Tty = val
		}
	}

	if param, ok := execMap["Container"]; ok {
		if val, ok := param.(string); ok {
			config.Container = val
		}
	}

	if param, ok := execMap["Cmd"]; ok {
		cmd := []string{}
		if list, ok := param.([]interface{}); ok {
			for _, item := range list {
				if val, ok := item.(string); ok {
					cmd = append(cmd, val)
				}
			}
		}
		config.Cmd = cmd
	}

	return config
}
