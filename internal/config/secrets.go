package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const (
	masterKeyEnvironment     = "BYOS_MASTER_KEY"
	adminPasswordEnvironment = "BYOS_ADMIN_PASSWORD"
	adminAPIKeyEnvironment   = "BYOS_ADMIN_API_KEY"
)

type Secrets struct {
	masterKey     [32]byte
	adminPassword string
	adminAPIKey   string
}

func LoadSecrets() (Secrets, error) {
	master, err := secretValue(masterKeyEnvironment)
	if err != nil {
		return Secrets{}, err
	}
	decoded, err := base64.StdEncoding.DecodeString(master)
	if err != nil || len(decoded) != 32 {
		return Secrets{}, fmt.Errorf("%s must be base64-encoded 32 bytes", masterKeyEnvironment)
	}
	password, err := secretValue(adminPasswordEnvironment)
	if err != nil {
		return Secrets{}, err
	}
	apiKey, err := secretValue(adminAPIKeyEnvironment)
	if err != nil {
		return Secrets{}, err
	}
	var key [32]byte
	copy(key[:], decoded)
	return Secrets{masterKey: key, adminPassword: password, adminAPIKey: apiKey}, nil
}

func secretValue(name string) (string, error) {
	if value := os.Getenv(name); value != "" {
		if strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		return value, nil
	}
	if path := os.Getenv(name + "_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s secret file: %w", name, err)
		}
		if value := strings.TrimSpace(string(data)); value != "" {
			return value, nil
		}
	}
	return "", fmt.Errorf("%s is required", name)
}

func (s Secrets) MasterKey() [32]byte   { return s.masterKey }
func (s Secrets) AdminPassword() string { return s.adminPassword }
func (s Secrets) AdminAPIKey() string   { return s.adminAPIKey }
