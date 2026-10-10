package stats

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/PastureStack/host-api/auth"
	"github.com/PastureStack/websocket-proxy/backend"
	"github.com/PastureStack/websocket-proxy/common"
	"github.com/moby/moby/client"
)

type StatsHandler struct {
}

func (s *StatsHandler) Handle(key string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message) {
	var audit *auth.StreamAudit
	defer func() {
		backend.SignalHandlerClosed(key, response)
		if audit != nil {
			audit.Report()
		}
	}()

	requestUrl, err := url.Parse(initialMessage)
	if err != nil {
		log.Error("Could not parse statistics request URL.")
		return
	}
	tokenString := requestUrl.Query().Get("token")
	audit = auth.BeginStreamAudit(tokenString)
	token, valid := auth.GetAndCheckStreamToken(tokenString, requestUrl.Path)
	if !valid {
		log.Error("Invalid statistics token.")
		return
	}
	if !audit.Ready() {
		audit.Unavailable(key, response)
		return
	}
	audit.Authorized()

	id := ""
	parts := pathParts(requestUrl.Path)
	if len(parts) == 3 {
		id = parts[2]
	}
	containerIDs, resourceID, authorized := legacyStatsAuthorization(token, id)
	if !authorized {
		audit.Fail("HandshakeDenied")
		log.Error("Statistics token does not authorize the requested resource.")
		return
	}

	dclient, err := newDockerClient()
	if err != nil {
		audit.Fail("DockerFailure")
		log.WithFields(log.Fields{"error": err}).Error("Couldn't get docker client")
		return
	}
	defer dclient.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	stop := auth.StartStreamWatch(ctx, tokenString, token, func() { audit.Cancel("AuthorizationRevoked"); cancel(); reader.Close(); writer.Close() })
	defer stop()

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
		audit.Fail("StreamFailed")
		log.WithFields(log.Fields{"error": err, "id": id}).Error("Error getting memory capacity.")
		return
	}
	if id == "" {
		for {
			infos := []containerInfo{}

			cInfo, err := getRootContainerInfo(count)
			if err != nil {
				audit.Fail("StreamFailed")
				return
			}

			infos = append(infos, cInfo)
			for i := range infos {
				if len(infos[i].Stats) > 0 {
					infos[i].Stats[0].Timestamp = time.Now()
				}
			}

			err = writeAggregatedStats(resourceID, nil, "host", infos, uint64(memLimit), writer)
			if err != nil {
				return
			}

			time.Sleep(1 * time.Second)
			count = 1
		}
	} else {
		inspect, err := dclient.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if err != nil {
			audit.Fail("DockerFailure")
			log.WithFields(log.Fields{"error": err}).Error("Can not inspect containers")
			return
		}
		statsResult, err := dclient.ContainerStats(ctx, id, client.ContainerStatsOptions{Stream: true})
		if err != nil {
			audit.Fail("DockerFailure")
			log.WithFields(log.Fields{"error": err}).Error("Can not get stats reader from docker")
			return
		}
		defer statsResult.Body.Close()
		pid := inspect.Container.State.Pid
		bufioReader := bufio.NewReader(statsResult.Body)
		for {
			infos := []containerInfo{}
			cInfo, err := getContainerStats(bufioReader, count, id, pid)

			if err != nil {
				if errors.Is(err, io.EOF) {
					audit.Succeed()
				} else {
					audit.Fail("DockerFailure")
				}
				log.WithFields(log.Fields{"error": err, "id": id}).Error("Error getting container info.")
				return
			}
			infos = append(infos, cInfo)
			for i := range infos {
				if len(infos[i].Stats) > 0 {
					infos[i].Stats[0].Timestamp = time.Now()
				}
			}

			err = writeAggregatedStats(id, containerIDs, "container", infos, uint64(memLimit), writer)
			if err != nil {
				return
			}

			time.Sleep(1 * time.Second)
			count = 1
		}
	}
}
