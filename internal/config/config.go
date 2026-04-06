package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config represents the main application configuration
type Config struct {
	Proxy    ProxyConfig    `toml:"proxy"`
	Admin    AdminConfig    `toml:"admin"`
	Database DatabaseConfig `toml:"database"`
	Logging  LoggingConfig  `toml:"logging"`
}

// ProxyConfig contains HTTP proxy settings
type ProxyConfig struct {
	Bind string `toml:"bind"`
}

// AdminConfig contains admin panel settings
type AdminConfig struct {
	Bind           string `toml:"bind"`
	DefaultUsername string `toml:"default_username"`
	DefaultPassword string `toml:"default_password"`
}

// DatabaseConfig contains database settings
type DatabaseConfig struct {
	Path string `toml:"path"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Path string `toml:"path"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Proxy: ProxyConfig{
			Bind: "0.0.0.0:8080",
		},
		Admin: AdminConfig{
			Bind:            "0.0.0.0:8081",
			DefaultUsername: "admin",
			DefaultPassword: "changeMe123!",
		},
		Database: DatabaseConfig{
			Path: "./randprox.db",
		},
		Logging: LoggingConfig{
			Path: "./randprox.log",
		},
	}
}

// Load loads the configuration from a TOML file
func Load(path string) (*Config, error) {
	config := DefaultConfig()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	if _, err := toml.DecodeFile(path, config); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	return config, nil
}

// Save saves the configuration to a TOML file
func (c *Config) Save(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	return toml.NewEncoder(file).Encode(c)
}
