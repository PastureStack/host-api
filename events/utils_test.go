package events

import (
	"fmt"
	"os"
	"testing"

	"github.com/fsouza/go-dockerclient"
)

func useEnvVars() bool {
	return os.Getenv("CATTLE_DOCKER_USE_BOOT2DOCKER") == "true"
}

func createContainer(client *docker.Client) (*docker.Container, error) {
	opts := docker.CreateContainerOptions{Config: &docker.Config{Image: "tianon/true"}}
	return client.CreateContainer(opts)
}

func createNetTestContainerNoLabel(client *docker.Client, ip string) (*docker.Container, error) {
	return createTestContainerInternal(client, ip, false, nil, true)
}

func createNetTestContainer(client *docker.Client, ip string) (*docker.Container, error) {
	return createTestContainerInternal(client, ip, true, nil, true)
}

func createTestContainer(client *docker.Client, ip string, labels map[string]string, isSystem bool) (*docker.Container, error) {
	return createTestContainerInternal(client, ip, true, labels, isSystem)
}

func createTestContainerInternal(client *docker.Client, ip string, useLabel bool, inputLabels map[string]string, isSystem bool) (*docker.Container, error) {
	labels := make(map[string]string)
	if inputLabels != nil {
		for k, v := range inputLabels {
			labels[k] = v
		}
	}
	if isSystem {
		labels["io.rancher.container.system"] = "FakeSysContainer"
	}

	env := []string{}
	if ip != "" {
		if useLabel {
			labels["io.rancher.container.ip"] = ip
		} else {
			env = append(env, "RANCHER_IP="+ip)
		}
	}

	config := &docker.Config{
		Image:     "busybox:latest",
		Labels:    labels,
		Env:       env,
		OpenStdin: true,
		StdinOnce: false,
	}
	opts := docker.CreateContainerOptions{Config: config}
	return client.CreateContainer(opts)
}

func requireTestImages(client *docker.Client) error {
	for _, imageName := range []string{"tianon/true:latest", "busybox:latest"} {
		if _, err := client.InspectImage(imageName); err != nil {
			return fmt.Errorf("required local test image %s is missing: %v", imageName, err)
		}
	}
	return nil
}

func TestMain(m *testing.M) {
	client, _ := NewDockerClient()
	if err := requireTestImages(client); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	result := m.Run()
	os.Exit(result)
}

func prep(t *testing.T) *docker.Client {
	dockerClient, err := NewDockerClient()
	if err != nil {
		t.Fatal(err)
	}

	return dockerClient
}
