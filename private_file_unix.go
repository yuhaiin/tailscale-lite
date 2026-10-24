//go:build !windows

package tailscalelite

import (
	"errors"
	"os"
)

func checkPrivateFile(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("state must be private (0600)")
	}
	return nil
}

func secureStateFile(f *os.File) error { return f.Chmod(0600) }
