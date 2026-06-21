package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// EntityDir returns the path to ~/.entity/.
func EntityDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(home, ".entity"), nil
}

// PeerDir returns the path to ~/.entity/peers/{name}/.
func PeerDir(name string) (string, error) {
	entityDir, err := EntityDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(entityDir, "peers", name), nil
}
