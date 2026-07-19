package stats

import "testing"

func TestConvertDockerStatsUsesUserModeAndClampsNegativeValues(t *testing.T) {
	input := DockerStats{}
	input.CPUStats.CPUUsage.TotalUsage = 12
	input.CPUStats.CPUUsage.UsageInUsermode = 7
	input.CPUStats.CPUUsage.UsageInKernelmode = 5
	input.MemoryStats.Usage = -1
	input.BlkioStats.IoServiceBytesRecursive = append(input.BlkioStats.IoServiceBytesRecursive, struct {
		Major int64  `json:"major"`
		Minor int64  `json:"minor"`
		Op    string `json:"op"`
		Value int64  `json:"value"`
	}{Major: 8, Minor: 1, Op: "Read", Value: -5})

	converted := convertDockerStats(input, -1)
	if converted.Cpu.Usage.User != 7 || converted.Cpu.Usage.System != 5 || converted.Cpu.Usage.Total != 12 {
		t.Fatalf("unexpected CPU conversion: %#v", converted.Cpu.Usage)
	}
	if converted.Memory.Usage != 0 {
		t.Fatalf("negative memory usage was not clamped: %d", converted.Memory.Usage)
	}
	if len(converted.DiskIo.IoServiceBytes) != 1 || converted.DiskIo.IoServiceBytes[0].Major != 8 || converted.DiskIo.IoServiceBytes[0].Stats["Read"] != 0 {
		t.Fatalf("unexpected disk conversion: %#v", converted.DiskIo.IoServiceBytes)
	}
}

func TestAggregationSkipsEmptySamples(t *testing.T) {
	result := convertToAggregatedStats("id", nil, "container", []containerInfo{{Id: "container"}}, 1024)
	if len(result) != 0 {
		t.Fatalf("empty sample produced output: %#v", result)
	}
}

func TestContainerStatsAuthorizationUsesExactContainerID(t *testing.T) {
	allowed := map[string]string{"0123456789abcdef": "resource-1"}
	if !containerStatsAuthorized("0123456789abcdef", allowed) {
		t.Fatal("authorized container ID was rejected")
	}
	for _, candidate := range []string{"", "0123456789abcde", "other-container"} {
		if containerStatsAuthorized(candidate, allowed) {
			t.Fatalf("unauthorized container ID was accepted: %q", candidate)
		}
	}
}
