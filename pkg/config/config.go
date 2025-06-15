package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration for the SQD agent
type Config struct {
	// General settings
	LogLevel      string        `yaml:"logLevel"`
	MonitorPeriod time.Duration `yaml:"monitorPeriod"`
	AutoUpdate    bool          `yaml:"autoUpdate"`

	// Prometheus metrics settings
	Prometheus PrometheusConfig `yaml:"prometheus"`

	// GraphQL API settings
	GraphQL GraphQLConfig `yaml:"graphql"`
}

// PrometheusConfig contains Prometheus metrics-related settings
type PrometheusConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// GraphQLConfig contains GraphQL API-related settings
type GraphQLConfig struct {
	Endpoint string `yaml:"endpoint"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		LogLevel:      "info",
		MonitorPeriod: 1 * time.Minute,
		AutoUpdate:    true,
		Prometheus: PrometheusConfig{
			Enabled: true,
			Port:    9090,
			Path:    "/metrics",
		},
		GraphQL: GraphQLConfig{
			Endpoint: "https://subsquid.squids.live/subsquid-network-mainnet/graphql",
		},
	}
}

// LoadConfig loads the configuration from the given file path
func LoadConfig(path string) (*Config, error) {
	// Set default config
	config := DefaultConfig()

	// Read config file
	data, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, fmt.Errorf("config file not found at %s, using defaults", path)
		}
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Parse YAML
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	return config, nil
}

// SaveConfig saves the configuration to the given file path
func SaveConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("error marshaling config: %w", err)
	}

	err = ioutil.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	return nil
}
