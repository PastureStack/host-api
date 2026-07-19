package dockersocketproxy

import (
	"encoding/base64"
	"io"
	"net"
	"net/url"

	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/host-api/auth"
	"github.com/PastureStack/websocket-proxy/backend"
	"github.com/PastureStack/websocket-proxy/common"
)

type Handler struct {
}

func (s *Handler) Handle(key string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message) {
	defer backend.SignalHandlerClosed(key, response)

	requestUrl, err := url.Parse(initialMessage)
	if err != nil {
		log.Error("Could not parse Docker socket request URL.")
		return
	}
	tokenString := requestUrl.Query().Get("token")
	token, valid := auth.GetAndCheckToken(tokenString)
	if !valid || !auth.HasScope(token, "dockersocket") {
		log.Error("Docker socket token is invalid or missing its required scope.")
		return
	}

	conn, err := net.Dial("unix", "/var/run/docker.sock")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Couldn't dial docker socket.")
		return
	}

	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer func() {
			close(done)
			conn.Close()
		}()

		for {
			msg, ok := <-incomingMessages
			if !ok {
				return
			}
			data, err := base64.StdEncoding.DecodeString(msg)

			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Error decoding message.")
				return
			}
			if _, err := conn.Write(data); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Error write message.")
				return
			}
		}
	}()

	for {
		buff := make([]byte, 1024)
		n, err := conn.Read(buff)
		if n > 0 {
			text := base64.StdEncoding.EncodeToString(buff[:n])
			message := common.Message{
				Key:  key,
				Type: common.Body,
				Body: text,
			}
			response <- message
		}
		if err != nil {
			if err != io.EOF {
				select {
				case <-done:
				default:
					log.WithFields(log.Fields{"error": err}).Error("Error reading Docker socket response.")
				}
			}
			return
		}
	}
}
