package stats

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/moby/moby/client"
)

func newDockerClient() (*client.Client, error) {
	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		host = client.DefaultDockerHost
	}
	hostURL, err := client.ParseHostURL(host)
	if err != nil {
		return nil, fmt.Errorf("parse Docker host: %w", err)
	}

	options := []client.Opt{client.WithHost(host)}
	if hostURL.Scheme == "tcp" {
		if os.Getenv("DOCKER_TLS_VERIFY") == "" {
			return nil, fmt.Errorf("DOCKER_TLS_VERIFY is required for a remote Docker host")
		}
		dockerCertPath := os.Getenv("DOCKER_CERT_PATH")
		if dockerCertPath == "" {
			return nil, fmt.Errorf("DOCKER_CERT_PATH is required for a remote Docker host")
		}
		options = append(options, client.WithTLSClientConfig(
			filepath.Join(dockerCertPath, "ca.pem"),
			filepath.Join(dockerCertPath, "cert.pem"),
			filepath.Join(dockerCertPath, "key.pem"),
		))
	}
	if apiVersion := os.Getenv("DOCKER_API_VERSION"); apiVersion != "" {
		options = append(options, client.WithAPIVersion(apiVersion))
	}
	return client.New(options...)
}
