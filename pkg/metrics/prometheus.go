package metrics

import (
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/nodexeus/sqd-network-monitor/pkg/config"
	"github.com/nodexeus/sqd-network-monitor/pkg/monitor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// NodeStatusProvider is a function type for getting node statuses
type NodeStatusProvider func() map[string]*monitor.NodeStatus

// PrometheusExporter exports metrics to Prometheus
type PrometheusExporter struct {
	config          *config.Config
	getNodeStatuses NodeStatusProvider
	registry        *prometheus.Registry

	// Node metrics
	nodeAPR               *prometheus.GaugeVec
	nodeJailed            *prometheus.GaugeVec
	nodeOnline            *prometheus.GaugeVec
	nodeQueries24Hours    *prometheus.GaugeVec
	nodeUptime24Hours     *prometheus.GaugeVec
	nodeServedData24Hours *prometheus.GaugeVec
	nodeStoredData        *prometheus.GaugeVec
	nodeTotalDelegation   *prometheus.GaugeVec
	nodeClaimedReward     *prometheus.GaugeVec
	nodeClaimableReward   *prometheus.GaugeVec
	nodeHealthy           *prometheus.GaugeVec

	// GraphQL client metrics
	graphQLQueryDuration   *prometheus.HistogramVec
	graphQLWorkersReturned *prometheus.GaugeVec
	graphQLQueryErrors     *prometheus.CounterVec

	server *http.Server
}

// NewPrometheusExporter creates a new Prometheus exporter
func NewPrometheusExporter(cfg *config.Config, getNodeStatuses NodeStatusProvider) *PrometheusExporter {
	// Create a new registry
	registry := prometheus.NewRegistry()

	exporter := &PrometheusExporter{
		config:          cfg,
		getNodeStatuses: getNodeStatuses,
		registry:        registry,
		nodeAPR: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_apr",
				Help: "Annual Percentage Rate (APR) of the SQD node",
			},
			[]string{"peer_id", "name", "version", "created_at", "status"},
		),
		nodeJailed: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_jailed",
				Help: "Whether the SQD node is jailed (1) or not (0)",
			},
			[]string{"peer_id", "name", "reason", "version"},
		),
		nodeOnline: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_online",
				Help: "Status of the SQD node on the network: 0=offline, 1=online, 2=unregistered (exists but not yet registered on network)",
			},
			[]string{"peer_id", "name", "version", "created_at", "status"},
		),
		nodeQueries24Hours: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_queries_24h",
				Help: "Number of queries made to the SQD node in the last 24 hours",
			},
			[]string{"peer_id", "name", "version", "created_at", "status"},
		),
		nodeUptime24Hours: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_uptime_24h",
				Help: "Uptime of the SQD node in the last 24 hours",
			},
			[]string{"peer_id", "name", "version", "created_at", "status"},
		),
		nodeServedData24Hours: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_served_data_24h",
				Help: "Number of bytes served by the SQD node in the last 24 hours",
			},
			[]string{"peer_id", "name", "version", "created_at", "status"},
		),
		nodeStoredData: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_stored_data",
				Help: "Number of bytes stored by the SQD node",
			},
			[]string{"peer_id", "name", "version", "created_at", "status"},
		),
		nodeTotalDelegation: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_total_delegation",
				Help: "Total delegation to the SQD node",
			},
			[]string{"peer_id", "name", "version", "created_at", "status"},
		),
		nodeClaimedReward: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_claimed_reward",
				Help: "Number of rewards claimed by the SQD node",
			},
			[]string{"peer_id", "name", "version", "created_at", "status"},
		),
		nodeClaimableReward: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_claimable_reward",
				Help: "Number of rewards claimable by the SQD node",
			},
			[]string{"peer_id", "name", "version", "created_at", "status"},
		),
		nodeHealthy: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_node_healthy",
				Help: "Whether the SQD node is healthy (1) or not (0)",
			},
			[]string{"peer_id", "name", "version", "created_at", "status"},
		),

		// GraphQL client metrics
		graphQLQueryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "sqd_graphql_query_duration_seconds",
				Help:    "Duration of GraphQL queries in seconds",
				Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"operation"},
		),

		graphQLWorkersReturned: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "sqd_graphql_workers_returned",
				Help: "Number of workers returned by GraphQL queries",
			},
			[]string{"operation"},
		),

		graphQLQueryErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sqd_graphql_query_errors_total",
				Help: "Total number of GraphQL query errors",
			},
			[]string{"operation", "error_type"},
		),
	}

	// Register metrics with the registry
	registry.MustRegister(
		exporter.nodeAPR,
		exporter.nodeJailed,
		exporter.nodeOnline,
		exporter.nodeQueries24Hours,
		exporter.nodeUptime24Hours,
		exporter.nodeServedData24Hours,
		exporter.nodeStoredData,
		exporter.nodeTotalDelegation,
		exporter.nodeClaimedReward,
		exporter.nodeClaimableReward,
		exporter.nodeHealthy,
		exporter.graphQLQueryDuration,
		exporter.graphQLWorkersReturned,
		exporter.graphQLQueryErrors,
	)

	return exporter
}

// Start starts the Prometheus exporter HTTP server
func (e *PrometheusExporter) Start() error {
	if !e.config.Prometheus.Enabled {
		return nil
	}

	// Create HTTP server
	mux := http.NewServeMux()

	// Create handler with the registry
	handler := promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})

	mux.Handle(e.config.Prometheus.Path, handler)

	// Bind to all interfaces
	addr := fmt.Sprintf("0.0.0.0:%d", e.config.Prometheus.Port)
	e.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Start HTTP server in a goroutine
	go func() {
		log.Infof("Starting Prometheus metrics server on port %d at path %s", e.config.Prometheus.Port, e.config.Prometheus.Path)
		if err := e.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Error starting Prometheus HTTP server: %v", err)
		}
	}()

	return nil
}

// Stop stops the Prometheus exporter HTTP server
func (e *PrometheusExporter) Stop() error {
	if e.server != nil {
		return e.server.Close()
	}
	return nil
}

// RecordGraphQLQueryDuration records the duration of a GraphQL query
func (e *PrometheusExporter) RecordGraphQLQueryDuration(operation string, duration time.Duration) {
	if e == nil || e.graphQLQueryDuration == nil {
		log.Warn("Attempted to record GraphQL query duration but metrics exporter is not properly initialized")
		return
	}
	e.graphQLQueryDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// SetGraphQLWorkersReturned sets the number of workers returned by a GraphQL query
func (e *PrometheusExporter) SetGraphQLWorkersReturned(operation string, count int) {
	if e == nil || e.graphQLWorkersReturned == nil {
		log.Warn("Attempted to set GraphQL workers returned but metrics exporter is not properly initialized")
		return
	}
	e.graphQLWorkersReturned.WithLabelValues(operation).Set(float64(count))
}

// IncGraphQLQueryErrors increments the error counter for GraphQL queries
func (e *PrometheusExporter) IncGraphQLQueryErrors(operation string, errorType string) {
	if e == nil || e.graphQLQueryErrors == nil {
		log.Warn("Attempted to increment GraphQL query errors but metrics exporter is not properly initialized")
		return
	}
	e.graphQLQueryErrors.WithLabelValues(operation, errorType).Inc()
}

// UpdateMetrics updates the Prometheus metrics based on the current node statuses
func (e *PrometheusExporter) UpdateMetrics() {
	if !e.config.Prometheus.Enabled {
		log.Debug("Prometheus metrics exporter is disabled, skipping metrics update")
		return
	}

	log.Debug("Updating Prometheus metrics...")

	// Get current node statuses
	log.Debug("Calling getNodeStatuses function...")
	statuses := e.getNodeStatuses()
	if statuses == nil {
		log.Error("getNodeStatuses returned nil")
		return
	}

	// Log the number of statuses
	log.Infof("Prometheus exporter: updating metrics with %d node statuses", len(statuses))

	// Debug logging to show actual statuses if present
	if len(statuses) > 0 {
		for instance, status := range statuses {
			if status == nil {
				log.Debugf("Node status for metrics: instance=%s, status is nil", instance)
				continue
			}
			log.Debugf("Node status for metrics: instance=%s, peerID=%s, name=%s, healthy=%v, online=%v, jailed=%v, apr=%f",
				instance, status.PeerID, status.Name, status.Healthy, status.Online, status.Jailed, status.APR)
		}
	} else {
		log.Warn("No node statuses available for metrics update - check monitor.GetNodeStatuses()")
	}

	// Reset all metrics to avoid stale data
	e.nodeAPR.Reset()
	e.nodeJailed.Reset()
	e.nodeOnline.Reset()
	e.nodeHealthy.Reset()
	e.nodeQueries24Hours.Reset()
	e.nodeUptime24Hours.Reset()
	e.nodeServedData24Hours.Reset()
	e.nodeStoredData.Reset()
	e.nodeTotalDelegation.Reset()
	e.nodeClaimedReward.Reset()
	e.nodeClaimableReward.Reset()

	// Update metrics for each node
	for _, status := range statuses {
		// Skip nodes without a peer ID or with nil Online status
		if status.PeerID == "" {
			continue
		}

		labels := prometheus.Labels{
			"peer_id":    status.PeerID,
			"name":       status.Name,
			"version":    status.Version,
			"created_at": status.CreatedAt.Format(time.RFC3339),
			"status":     strings.ToLower(status.NetworkStatus),
		}

		// APR
		e.nodeAPR.With(labels).Set(status.APR)
		log.Debugf("Set APR metric for %s: %f", status.PeerID, status.APR)

		// Jailed status - include all required labels plus the reason
		jailedLabels := prometheus.Labels{
			"peer_id": status.PeerID,
			"name":    status.Name,
			"version": status.Version,
			"reason":  status.JailReason,
		}
		if status.Jailed {
			e.nodeJailed.With(jailedLabels).Set(1)
			log.Debugf("Set jailed metric for %s: 1", status.PeerID)
		} else {
			e.nodeJailed.With(jailedLabels).Set(0)
			log.Debugf("Set jailed metric for %s: 0", status.PeerID)
		}

		// Online status - now with 3 states:
		// 0: Offline (node is registered but offline)
		// 1: Online (node is registered and online)
		// 2: Unregistered (node exists but not yet registered on network)
		if status.NetworkStatus == "unregistered" {
			// Value 2 represents unregistered state
			e.nodeOnline.With(labels).Set(2)
			log.Debugf("Set online metric for %s: 2 (unregistered)", status.PeerID)
		} else if status.Online {
			// Value 1 represents online state
			e.nodeOnline.With(labels).Set(1)
			log.Debugf("Set online metric for %s: 1 (online)", status.PeerID)
		} else if !status.Online {
			// Value 0 represents offline state (explicitly set to false)
			e.nodeOnline.With(labels).Set(0)
			log.Debugf("Set online metric for %s: 0 (offline)", status.PeerID)
		} else {
			// Handle case where Online is nil (not set)
			e.nodeOnline.With(labels).Set(-1)
			log.Debugf("Set online metric for %s: -1 (status not reported)", status.PeerID)
		}

		// Healthy status
		if status.Healthy {
			e.nodeHealthy.With(labels).Set(1)
			log.Debugf("Set healthy metric for %s: 1", status.PeerID)
		} else {
			e.nodeHealthy.With(labels).Set(0)
			log.Debugf("Set healthy metric for %s: 0", status.PeerID)
		}

		// Queries24Hours
		if status.Queries24Hours >= 0 {
			e.nodeQueries24Hours.With(labels).Set(float64(status.Queries24Hours))
			log.Debugf("Set queries24Hours metric for %s: %d", status.PeerID, status.Queries24Hours)
		}

		// Uptime24Hours
		if status.Uptime24Hours >= 0 {
			e.nodeUptime24Hours.With(labels).Set(float64(status.Uptime24Hours))
			log.Debugf("Set uptime24Hours metric for %s: %f", status.PeerID, status.Uptime24Hours)
		}

		// ServedData24Hours
		if status.ServedData24Hours >= 0 {
			e.nodeServedData24Hours.With(labels).Set(float64(status.ServedData24Hours))
			log.Debugf("Set servedData24Hours metric for %s: %d", status.PeerID, status.ServedData24Hours)
		}

		// StoredData
		if status.StoredData != nil && status.StoredData.Sign() >= 0 {
			// Convert big.Int to float64 for Prometheus
			storedData, _ := new(big.Float).SetInt(status.StoredData).Float64()
			e.nodeStoredData.With(labels).Set(storedData)
			log.Debugf("Set storedData metric for %s: %s", status.PeerID, status.StoredData.String())
		}

		// TotalDelegation
		if status.TotalDelegation != nil && status.TotalDelegation.Sign() >= 0 {
			// Convert big.Int to float64 for Prometheus
			totalDelegation, _ := new(big.Float).SetInt(status.TotalDelegation).Float64()
			e.nodeTotalDelegation.With(labels).Set(totalDelegation)
			log.Debugf("Set totalDelegation metric for %s: %s", status.PeerID, status.TotalDelegation.String())
		}

		// ClaimedReward
		if status.ClaimedReward != nil && status.ClaimedReward.Sign() >= 0 {
			// Convert big.Int to float64 for Prometheus
			claimedReward, _ := new(big.Float).SetInt(status.ClaimedReward).Float64()
			e.nodeClaimedReward.With(labels).Set(claimedReward)
			log.Debugf("Set claimedReward metric for %s: %s", status.PeerID, status.ClaimedReward.String())
		}

		// ClaimableReward
		if status.ClaimableReward != nil && status.ClaimableReward.Sign() >= 0 {
			// Convert big.Int to float64 for Prometheus
			claimableReward, _ := new(big.Float).SetInt(status.ClaimableReward).Float64()
			e.nodeClaimableReward.With(labels).Set(claimableReward)
			log.Debugf("Set claimableReward metric for %s: %s", status.PeerID, status.ClaimableReward.String())
		}
	}

	log.Info("Prometheus metrics update completed")
}
