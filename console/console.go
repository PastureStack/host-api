package console

import (
	"encoding/base64"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/host-api/auth"
	"github.com/PastureStack/websocket-proxy/backend"
	"github.com/PastureStack/websocket-proxy/common"
)

const vmSocketRoot = "/var/lib/rancher/vm"

var safeContainerID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Handler struct {
}

func (s *Handler) Handle(key string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message) {
	defer backend.SignalHandlerClosed(key, response)
	requestUrl, err := url.Parse(initialMessage)
	if err != nil {
		log.Error("Could not parse console request URL.")
		return
	}
	tokenString := requestUrl.Query().Get("token")
	token, valid := auth.GetAndCheckToken(tokenString)
	if !valid {
		return
	}

	console, ok := auth.GetClaimMap(token, "console")
	if !ok {
		log.Error("Token missing console claim.")
		return
	}
	container, ok := auth.GetMapString(console, "container")
	if !ok || !safeContainerID.MatchString(container) {
		log.Error("Token contains an invalid console container claim.")
		return
	}

	socketLoc := filepath.Join(vmSocketRoot, container, "vnc")
	conn, err := net.DialTimeout("unix", socketLoc, 10*time.Second)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Errorf("Couldn't dial VM socket [%v].", socketLoc)
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
					log.WithFields(log.Fields{"error": err}).Error("Error reading console response.")
				}
			}
			return
		}
	}
}
