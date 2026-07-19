package stats

import "testing"

func TestRemoteDockerClientRequiresVerifiedTLS(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:2376")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	if _, err := newDockerClient(); err == nil {
		t.Fatal("remote Docker client accepted an unverified connection")
	}
}

func TestLocalDockerClientRemainsAvailable(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	client, err := newDockerClient()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
}
