package exec

import "testing"

func TestConvertExecConfiguration(t *testing.T) {
	converted := convert(map[string]interface{}{
		"AttachStdin":  true,
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          true,
		"Container":    "container-1",
		"Cmd":          []interface{}{"sh", "-lc", "echo ok", 7},
	})
	if converted.Container != "container-1" || len(converted.Cmd) != 3 || converted.Cmd[2] != "echo ok" {
		t.Fatalf("unexpected exec conversion: %#v", converted)
	}
}
