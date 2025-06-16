package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nodexeus/sqd-network-monitor/pkg/api"
	"github.com/nodexeus/sqd-network-monitor/pkg/config"
	"github.com/nodexeus/sqd-network-monitor/pkg/discovery"
	"github.com/nodexeus/sqd-network-monitor/pkg/metrics"
	"github.com/nodexeus/sqd-network-monitor/pkg/monitor"
	"github.com/nodexeus/sqd-network-monitor/pkg/updater"
	log "github.com/sirupsen/logrus"
)

var (
	configPath  = flag.String("config", "/etc/sqd-network-monitor/config.yaml", "Path to config file")
	showVersion = flag.Bool("version", false, "Show version information and exit")
	version     = "0.1.1"
	buildTime   = "unknown"
)

func main() {
	flag.Parse()

	// Print version
	if *showVersion {
		fmt.Printf("SQD Agent v%s (built at %s)\n", version, buildTime)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Warnf("Warning: %v", err)
	}

	// Configure logging
	configureLogging(cfg.LogLevel)
	log.Info("Starting SQD Agent v", version)
	log.Infof("Configuration loaded - AutoUpdate: %v", cfg.AutoUpdate)

	// Get system hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	log.Infof("Running on host: %s", hostname)

	// Declare all variables at the beginning of the function
	var (
		mon                *monitor.Monitor
		apiClient          *api.GraphQLClient
		prometheusExporter *metrics.PrometheusExporter
		discoverer         monitor.Discoverer
		upd                *updater.Updater
	)

	// Initialize API client first with nil metrics
	apiClient = api.NewGraphQLClient(cfg, nil)

	// Initialize node discoverer to fetch nodes from GraphQL API
	discoverer = discovery.NewGraphQLDiscoverer(apiClient)
	log.Info("Using GraphQL API for node discovery")

	// Create and initialize monitor with GraphQL-based node discovery
	mon = monitor.NewMonitor(cfg, apiClient, discoverer)

	// Initialize Prometheus metrics if enabled
	if cfg.Prometheus.Enabled {
		// Create a status function that uses the monitor
		statusFn := func() map[string]*monitor.NodeStatus {
			if mon == nil {
				log.Warn("Monitor is not initialized yet, returning empty node statuses")
				return make(map[string]*monitor.NodeStatus)
			}
			return mon.GetNodeStatuses()
		}

		// Create and start the Prometheus exporter
		prometheusExporter = metrics.NewPrometheusExporter(cfg, statusFn)
		if err := prometheusExporter.Start(); err != nil {
			log.Fatalf("Failed to start Prometheus exporter: %v", err)
		}

		// Set the metrics exporter on both the monitor and API client
		mon.SetMetricsExporter(prometheusExporter)
		apiClient.SetMetricsExporter(prometheusExporter)

		log.Info("Prometheus metrics exporter configured and started")
	}

	// Create updater
	upd = nil
	if cfg.AutoUpdate {
		log.Info("Auto-update is enabled in config, initializing updater...")
		upd, err = updater.NewUpdater(version)
		if err != nil {
			log.Warnf("Warning: Failed to create updater: %v", err)
		} else {
			// Start the update checker in a goroutine
			log.Info("Auto-update enabled, starting update checker")
			updCtx, updCancel := context.WithCancel(context.Background())
			defer updCancel()

			// Start update checker
			updateTicker := time.NewTicker(2 * time.Minute)
			initialDelay := time.After(30 * time.Second)

			// Initial check after delay
			updateCheck := func() {
				log.Info("Checking for updates...")
				release, err := upd.CheckForUpdates()
				if err != nil {
					log.Errorf("Error checking for updates: %v", err)
					return
				}
				if release != nil {
					log.Infof("Update available: %s", release.Version)
					if err := upd.Update(release); err != nil {
						log.Errorf("Failed to apply update: %v", err)
					}
				}
			}

			go func() {
				// Initial check after delay
				select {
				case <-initialDelay:
					updateCheck()
				case <-updCtx.Done():
					updateTicker.Stop()
					return
				}

				// Periodic checks
				for {
					select {
					case <-updateTicker.C:
						updateCheck()
					case <-updCtx.Done():
						updateTicker.Stop()
						return
					}
				}
			}()
		}
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor
	if err := mon.Start(ctx); err != nil {
		log.Fatalf("Failed to start monitor: %v", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for termination signal
	sig := <-sigChan
	log.Infof("Received signal %v, shutting down...", sig)

	// Cancel context to stop all background tasks
	cancel()

	// Stop Prometheus exporter
	if prometheusExporter != nil {
		if err := prometheusExporter.Stop(); err != nil {
			log.Errorf("Error stopping Prometheus exporter: %v", err)
		}
	}

	log.Info("Shutdown complete")

	// Check for updates before exiting
	if upd != nil {
		log.Info("Checking for updates...")
		releaseInfo, err := upd.CheckForUpdates()
		if err != nil {
			log.Errorf("Error checking for updates: %v", err)
		} else if releaseInfo != nil {
			log.Infof("New version available: %s", releaseInfo.Version)
			if err := upd.Update(releaseInfo); err != nil {
				log.Errorf("Error updating: %v", err)
			} else {
				log.Infof("Update to version %s scheduled for next restart", releaseInfo.Version)
			}
		} else {
			log.Info("No updates available")
		}
	}
}

// configureLogging sets up the logging based on the configured log level
func configureLogging(logLevel string) {
	// Set log formatter
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	// Set output to stdout
	log.SetOutput(os.Stdout)

	// Set log level
	switch logLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn", "warning":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}
