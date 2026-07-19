package console

import "testing"

func TestConsoleContainerIdentifierRejectsTraversal(t *testing.T) {
	for _, value := range []string{"../vm", "a/b", "", ".", ".."} {
		if safeContainerID.MatchString(value) {
			t.Fatalf("unsafe console container identifier was accepted: %q", value)
		}
	}
	for _, value := range []string{"1vm1", "vm-123_abc.example"} {
		if !safeContainerID.MatchString(value) {
			t.Fatalf("valid console container identifier was rejected: %q", value)
		}
	}
}
