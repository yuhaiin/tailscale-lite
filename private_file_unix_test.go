//go:build !windows

package tailscalelite

import (
	"os"
	"testing"
)

func makeStatePublic(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
}
