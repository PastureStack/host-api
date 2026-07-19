package events

import "testing"

func TestExternalDockerRequiresVerifiedTLS(t *testing.T) {
	t.Setenv("PASTURESTACK_DOCKER_USE_BOOT2DOCKER", "true")
	t.Setenv("CATTLE_DOCKER_USE_BOOT2DOCKER", "")
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:2376")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	if _, err := NewDockerClient(); err == nil {
		t.Fatal("external Docker client accepted an unverified connection")
	}
}
