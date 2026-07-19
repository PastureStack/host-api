package events

import (
	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/platformapi"
	"github.com/PastureStack/host-api/util"
	"github.com/fsouza/go-dockerclient"
)

const (
	simulatedEvent = "-simulated-"
)

func NewDockerEventsProcessor(poolSize int) *DockerEventsProcessor {
	return &DockerEventsProcessor{
		poolSize:          poolSize,
		getDockerClient:   getDockerClientFn,
		getHandlers:       getHandlersFn,
		getPlatformClient: util.GetPlatformClient,
	}
}

type DockerEventsProcessor struct {
	poolSize          int
	getDockerClient   func() (*docker.Client, error)
	getHandlers       func(*docker.Client, *platformapi.Client) (map[string][]Handler, error)
	getPlatformClient func() (*platformapi.Client, error)
}

func (de *DockerEventsProcessor) Process() error {
	dockerClient, err := de.getDockerClient()
	if err != nil {
		return err
	}

	platformClient, err := de.getPlatformClient()
	if err != nil {
		return err
	}

	handlers, err := de.getHandlers(dockerClient, platformClient)
	if err != nil {
		return err
	}

	router, err := NewEventRouter(de.poolSize, de.poolSize, dockerClient, handlers)
	if err != nil {
		return err
	}
	if err := router.Start(); err != nil {
		return err
	}

	listOpts := docker.ListContainersOptions{
		All:     true,
		Filters: map[string][]string{"status": {"paused", "running"}},
	}
	containers, err := dockerClient.ListContainers(listOpts)
	if err != nil {
		_ = router.Stop()
		return err
	}

	for _, c := range containers {
		event := &docker.APIEvents{
			ID:     c.ID,
			Status: "start",
			From:   simulatedEvent,
		}
		router.listener <- event
	}
	return nil
}

func getDockerClientFn() (*docker.Client, error) {
	return NewDockerClient()
}

func getHandlersFn(dockerClient *docker.Client, platformClient *platformapi.Client) (map[string][]Handler, error) {

	handlers := map[string][]Handler{}

	// Control-platform event handler.
	if platformClient != nil {
		sendToPlatformHandler := &SendToPlatformHandler{
			client:   dockerClient,
			platform: platformClient.ContainerEvent,
			hostUuid: getHostUuid(),
		}
		handlers["start"] = append(handlers["start"], sendToPlatformHandler)
		handlers["stop"] = []Handler{sendToPlatformHandler}
		handlers["die"] = []Handler{sendToPlatformHandler}
		handlers["kill"] = []Handler{sendToPlatformHandler}
		handlers["destroy"] = []Handler{sendToPlatformHandler}
	}

	return handlers, nil
}

func getHostUuid() string {
	return config.Config.HostUuid
}
