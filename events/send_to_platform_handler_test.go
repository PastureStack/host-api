package events

import (
	"github.com/PastureStack/host-api/platformapi"
	"github.com/fsouza/go-dockerclient"
	"testing"
)

func TestSendToPlatformHandler(t *testing.T) {
	dockerClient := prep(t)

	injectedIp := "10.1.2.3"
	c, _ := createNetTestContainer(dockerClient, injectedIp)
	defer dockerClient.RemoveContainer(docker.RemoveContainerOptions{ID: c.ID, Force: true, RemoveVolumes: true})

	from := "foo/bar"
	status := "create"
	var eventTime int64 = 1426091566
	hostUuid := "host-123"
	event := &docker.APIEvents{ID: c.ID, From: from, Status: status, Time: eventTime}
	expectedEvent := &platformapi.ContainerEvent{
		ExternalID:        c.ID,
		ExternalFrom:      from,
		ExternalStatus:    status,
		ExternalTimestamp: eventTime,
		ReportedHostUUID:  hostUuid,
	}
	platform := mockPlatformClient(expectedEvent, t)

	handler := &SendToPlatformHandler{client: dockerClient, platform: platform, hostUuid: hostUuid}

	if err := handler.Handle(event); err != nil {
		t.Fatal(err)
	}
}

func mockPlatformClient(expectedEvent *platformapi.ContainerEvent, t *testing.T) platformapi.ContainerEventCreator {
	return &MockContainerEventOps{t: t, expectedEvent: expectedEvent}
}

type MockContainerEventOps struct {
	expectedEvent *platformapi.ContainerEvent
	t             *testing.T
}

func (m *MockContainerEventOps) Create(event *platformapi.ContainerEvent) (*platformapi.ContainerEvent, error) {
	if m.expectedEvent == nil {
		return event, nil
	}
	if event.ExternalID != m.expectedEvent.ExternalID ||
		event.ExternalFrom != m.expectedEvent.ExternalFrom ||
		event.ExternalTimestamp != m.expectedEvent.ExternalTimestamp ||
		event.ExternalStatus != m.expectedEvent.ExternalStatus ||
		event.ReportedHostUUID != m.expectedEvent.ReportedHostUUID ||
		event.DockerInspect == nil {
		m.t.Fatalf("Events don't match. Expected: %#v; Actual: %#v", m.expectedEvent, event)
	}
	return event, nil
}
