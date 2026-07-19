package stats

import (
	"bufio"
	"io"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/host-api/auth"
	"github.com/PastureStack/websocket-proxy/backend"
	"github.com/PastureStack/websocket-proxy/common"
)

type HostStatsHandler struct {
}

func (s *HostStatsHandler) Handle(key string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message) {
	defer backend.SignalHandlerClosed(key, response)

	requestUrl, err := url.Parse(initialMessage)
	if err != nil {
		log.Error("Could not parse host statistics request URL.")
		return
	}

	tokenString := requestUrl.Query().Get("token")

	token, valid := auth.GetAndCheckToken(tokenString)
	if !valid {
		log.Error("Invalid host statistics token.")
		return
	}
	resourceId, authorized := getResourceIDClaim(token)
	if !authorized {
		log.Error("Host statistics token is missing a valid resource claim.")
		return
	}

	reader, writer := io.Pipe()

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
			log.WithFields(log.Fields{"error": err}).Error("Error with the container stat scanner.")
		}
	}(reader)

	count := 1
	memLimit, err := getMemCapcity()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error getting memory capacity.")
		return
	}

	for {
		infos := []containerInfo{}

		cInfo, err := getRootContainerInfo(count)
		if err != nil {
			return
		}

		infos = append(infos, cInfo)
		for i := range infos {
			if len(infos[i].Stats) > 0 {
				infos[i].Stats[0].Timestamp = time.Now()
			}
		}

		err = writeAggregatedStats(resourceId, nil, "host", infos, uint64(memLimit), writer)
		if err != nil {
			return
		}

		time.Sleep(1 * time.Second)
		count = 1
	}
}
