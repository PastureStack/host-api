package events

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fsouza/go-dockerclient"
)

const (
	defaultUnixSocket = "unix:///var/run/docker.sock"
)

func NewDockerClient() (*docker.Client, error) {
	apiVersion := os.Getenv("DOCKER_API_VERSION")
	endpoint := defaultUnixSocket

	useExternalDocker := os.Getenv("PASTURESTACK_DOCKER_USE_BOOT2DOCKER") == "true" || os.Getenv("CATTLE_DOCKER_USE_BOOT2DOCKER") == "true"
	if useExternalDocker {
		endpoint = os.Getenv("DOCKER_HOST")
		if endpoint == "" {
			return nil, fmt.Errorf("DOCKER_HOST is required when external Docker mode is enabled")
		}
		certPath := os.Getenv("DOCKER_CERT_PATH")
		tlsVerify := os.Getenv("DOCKER_TLS_VERIFY") != ""
		if !tlsVerify {
			return nil, fmt.Errorf("DOCKER_TLS_VERIFY is required when external Docker mode is enabled")
		}
		if certPath == "" {
			return nil, fmt.Errorf("DOCKER_CERT_PATH is required when external Docker mode is enabled")
		}
		cert := filepath.Join(certPath, "cert.pem")
		key := filepath.Join(certPath, "key.pem")
		ca := filepath.Join(certPath, "ca.pem")
		if apiVersion == "" {
			return docker.NewTLSClient(endpoint, cert, key, ca)
		}
		return docker.NewVersionedTLSClient(endpoint, cert, key, ca, apiVersion)
	}

	if apiVersion == "" {
		return docker.NewClient(endpoint)
	}
	return docker.NewVersionedClient(endpoint, apiVersion)
}
