//go:build !linux

package auth

import "os"

// The production artifact is Linux. Other platforms retain filesystem checks.
func completionOwnedByProcess(os.FileInfo) bool  { return true }
func completionTrustedAncestor(os.FileInfo) bool { return true }
