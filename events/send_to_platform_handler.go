package events

import (
	"github.com/PastureStack/host-api/platformapi"
	"github.com/fsouza/go-dockerclient"
	log "github.com/sirupsen/logrus"
)

type SendToPlatformHandler struct {
	client   SimpleDockerClient
	platform platformapi.ContainerEventCreator
	hostUuid string
}

func (h *SendToPlatformHandler) Handle(event *docker.APIEvents) error {
	// The compatibility state watcher sends a simulated event to initiate IP injection.
	// This event should not be sent.
	if event.From == simulatedEvent {
		return nil
	}

	// Note: event.ID == container's ID
	unlock := eventLocks.tryLock(event.Status + event.ID)
	if unlock == nil {
		log.Debugf("Container locked. Can't run SendToPlatformHandler. Event: [%s], ID: [%s]", event.Status, event.ID)
		return nil
	}
	defer unlock()

	container, err := h.client.InspectContainer(event.ID)
	if err != nil {
		if _, ok := err.(*docker.NoSuchContainer); !ok {
			return err
		}
	}

	containerEvent := &platformapi.ContainerEvent{
		ExternalStatus:    event.Status,
		ExternalID:        event.ID,
		ExternalFrom:      event.From,
		ExternalTimestamp: int64(event.Time),
		ReportedHostUUID:  h.hostUuid,
	}
	if container != nil {
		containerEvent.DockerInspect = container

	}

	if _, err := h.platform.Create(containerEvent); err != nil {
		return err
	}

	return nil
}
