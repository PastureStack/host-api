package stats

import (
	"bufio"
	"context"
	"io"
	"net/url"
	"time"

	"github.com/PastureStack/host-api/auth"
	"github.com/PastureStack/websocket-proxy/backend"
	"github.com/PastureStack/websocket-proxy/common"
	"github.com/moby/moby/client"
	log "github.com/sirupsen/logrus"
)

type ContainerStatsHandler struct {
}

func (s *ContainerStatsHandler) Handle(key string, initialMessage string, incomingMessages <-chan string, response chan<- common.Message) {
	defer backend.SignalHandlerClosed(key, response)

	requestUrl, err := url.Parse(initialMessage)
	if err != nil {
		log.Error("Could not parse container statistics request URL.")
		return
	}

	tokenString := requestUrl.Query().Get("token")

	token, valid := auth.GetAndCheckToken(tokenString)
	containerIds, authorized := getContainerIDsClaim(token)

	id := ""
	parts := pathParts(requestUrl.Path)
	if len(parts) == 3 {
		id = parts[2]
	}

	if !valid || !authorized {
		log.WithField("id", id).Error("Invalid container statistics token.")
		return
	}
	if id != "" {
		if !containerStatsAuthorized(id, containerIds) {
			log.WithField("id", id).Error("Container statistics token does not authorize this container.")
			return
		}
	}

	dclient, err := newDockerClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Couldn't get docker client.")
		return
	}
	defer dclient.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader, writer := io.Pipe()

	go func(w *io.PipeWriter) {
		for {
			_, ok := <-incomingMessages
			if !ok {
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
		log.WithFields(log.Fields{"error": err, "id": id}).Error("Error getting memory capacity.")
		return
	}

	// get single container stats
	if id != "" {
		inspect, err := dclient.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Can not inspect containers")
			return
		}
		statsResult, err := dclient.ContainerStats(ctx, id, client.ContainerStatsOptions{Stream: true})
		if err != nil {
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
				log.WithFields(log.Fields{"error": err, "id": id}).Error("Error getting container info.")
				return
			}
			infos = append(infos, cInfo)
			for i := range infos {
				if len(infos[i].Stats) > 0 {
					infos[i].Stats[0].Timestamp = time.Now()
				}
			}

			err = writeAggregatedStats(id, containerIds, "container", infos, uint64(memLimit), writer)
			if err != nil {
				return
			}

			time.Sleep(1 * time.Second)
			count = 1
		}
	} else {
		contList, err := dclient.ContainerList(ctx, client.ContainerListOptions{})
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Can not list containers")
			return
		}
		IDList := []string{}
		bufioReaders := []*bufio.Reader{}
		pids := []int{}
		for _, cont := range contList.Items {
			if _, ok := containerIds[cont.ID]; ok {
				inspect, err := dclient.ContainerInspect(ctx, cont.ID, client.ContainerInspectOptions{})
				if err != nil {
					log.WithFields(log.Fields{"error": err}).Error("Can not inspect containers")
					return
				}
				statsResult, err := dclient.ContainerStats(ctx, cont.ID, client.ContainerStatsOptions{Stream: true})
				if err != nil {
					log.WithFields(log.Fields{"error": err}).Error("Can not get stats reader from docker")
					return
				}
				defer statsResult.Body.Close()
				pids = append(pids, inspect.Container.State.Pid)
				bufioReader := bufio.NewReader(statsResult.Body)
				bufioReaders = append(bufioReaders, bufioReader)
				IDList = append(IDList, cont.ID)
			}
		}
		for {
			infos := []containerInfo{}
			allInfos, err := getAllDockerContainers(bufioReaders, count, IDList, pids)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Error getting all container info.")
				return
			}
			infos = append(infos, allInfos...)
			for i := range infos {
				if len(infos[i].Stats) > 0 {
					infos[i].Stats[0].Timestamp = time.Now()
				}
			}
			err = writeAggregatedStats(id, containerIds, "container", infos, uint64(memLimit), writer)
			if err != nil {
				return
			}

			time.Sleep(1 * time.Second)
		}
	}
}

func containerStatsAuthorized(id string, containerIDs map[string]string) bool {
	_, allowed := containerIDs[id]
	return id != "" && allowed
}
