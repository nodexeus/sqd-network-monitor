package monitor

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/nodexeus/sqd-network-monitor/pkg/api"
	"github.com/nodexeus/sqd-network-monitor/pkg/config"
	log "github.com/sirupsen/logrus"
)

type NodeStatus struct {
	Instance          string // Unique identifier for the node (e.g., peer ID or custom name)
	PeerID            string
	Name              string
	NetworkStatus     string // For special statuses like "pending" for newly created nodes
	APR               float64
	Online            bool // true/false indicate actual status
	Jailed            bool
	JailReason        string
	Queries24Hours    int64
	Uptime24Hours     float64
	Version           string
	ServedData24Hours int64
	StoredData        *big.Int
	TotalDelegation   *big.Int
	ClaimedReward     *big.Int
	ClaimableReward   *big.Int
	CreatedAt         time.Time
	LastChecked       time.Time
	Healthy           bool
	Status            string
}

// DiscoveredNode represents a node discovered by a Discoverer
type DiscoveredNode struct {
	Instance string
	PeerID   string
	Name     string
	Version  string
}

// Discoverer is an interface for discovering nodes
type Discoverer interface {
	DiscoverNodes(ctx context.Context) ([]*DiscoveredNode, error)
}

// Monitor is responsible for monitoring SQD nodes
type Monitor struct {
	config          *config.Config
	apiClient       *api.GraphQLClient
	discoverer      Discoverer
	metricsExporter MetricsExporter
	nodes           map[string]*NodeStatus // Map of instance name to node status
}

// MetricsExporter is an interface for metrics exporters
type MetricsExporter interface {
	UpdateMetrics()
}

// NewMonitor creates a new node monitor
func NewMonitor(config *config.Config, apiClient *api.GraphQLClient, discoverer Discoverer) *Monitor {
	return &Monitor{
		config:          config,
		apiClient:       apiClient,
		discoverer:      discoverer,
		nodes:           make(map[string]*NodeStatus),
		metricsExporter: nil,
	}
}

// SetMetricsExporter sets the metrics exporter for the monitor
func (m *Monitor) SetMetricsExporter(exporter MetricsExporter) {
	m.metricsExporter = exporter
}

// Start starts the monitoring process
func (m *Monitor) Start(ctx context.Context) error {
	// Initial discovery and check
	if err := m.discoverAndCheck(ctx); err != nil {
		// Log the error but continue instead of failing
		log.Warnf("Initial node discovery failed: %v", err)
		log.Info("Agent will continue to run and retry on next monitor period")
	}

	// Start periodic monitoring
	monitorTicker := time.NewTicker(m.config.MonitorPeriod)

	go func() {
		for {
			select {
			case <-ctx.Done():
				monitorTicker.Stop()
				return
			case <-monitorTicker.C:
				if err := m.discoverAndCheck(ctx); err != nil {
					log.Errorf("Error during node discovery and check: %v", err)
				}
			}
		}
	}()

	return nil
}

// discoverAndCheck discovers nodes and checks their status
func (m *Monitor) discoverAndCheck(ctx context.Context) error {
	log.Debug("Starting discoverAndCheck")

	// Discover nodes
	nodes, err := m.discoverer.DiscoverNodes(ctx)
	if err != nil {
		return fmt.Errorf("failed to discover nodes: %w", err)
	}

	log.Debugf("Discovered %d nodes", len(nodes))

	// Get network status for each node
	networkStatuses := make(map[string]*api.NodeNetworkStatus)

	// Test GraphQL API connection if not connected
	if !m.apiClient.IsConnected() {
		log.Debug("GraphQL API connection not established, testing connection...")
		if !m.apiClient.TestConnection(ctx) {
			log.Warnf("GraphQL API connection is down. Last error: %v (occurred %s ago)",
				m.apiClient.GetLastError(),
				time.Since(m.apiClient.GetLastErrorTime()).Round(time.Second))
			log.Info("Will continue with local status only and retry connection on next check")
		} else {
			log.Info("Successfully established connection to GraphQL API")
		}
	}

	// If we have a connection, fetch network status for all nodes at once
	if m.apiClient.IsConnected() {
		log.Debug("GraphQL API is connected, fetching network status for all nodes")
		statuses, err := m.apiClient.GetNodeNetworkStatuses(ctx)
		if err != nil {
			log.Errorf("Failed to get network statuses: %v", err)
			if !m.apiClient.IsConnected() {
				log.Warn("GraphQL API connection lost, will retry on next check")
			} else {
				// If we have nodes but couldn't get any statuses, log a warning but continue
				if len(nodes) > 0 {
					log.Warnf("Failed to get network status for any nodes: %v", err)
				}
			}
		} else {
			// Create a map of peer ID to status for easy lookup
			statusMap := make(map[string]*api.NodeNetworkStatus, len(statuses))
			for _, status := range statuses {
				if status.PeerID == "" {
					log.Warn("Received status with empty peer ID, skipping")
					continue
				}
				statusMap[status.PeerID] = status

				log.Debugf("Retrieved network status for node %s: online=%v, jailed=%v, jailReason=%s, name=%s, apr=%f, peerID=%s, version=%s, claimedReward=%d, claimableReward=%d, servedData24Hours=%d, storedData=%d, totalDelegation=%d, uptime24Hours=%f, queries24Hours=%d",
					status.PeerID, status.Online, status.Jailed, status.JailReason, status.Name, status.APR, status.PeerID, status.Version, status.ClaimedReward, status.ClaimableReward, status.ServedData24Hours, status.StoredData, status.TotalDelegation, status.Uptime24Hours, status.Queries24Hours)
			}

			// Match the statuses with our discovered nodes
			for _, node := range nodes {
				if node.PeerID == "" {
					log.Debugf("Skipping network status for node %s: no peer ID", node.Instance)
					continue
				}

				if status, exists := statusMap[node.PeerID]; exists {
					if status.Name == "" {
						log.Debugf("Node %s (peer ID: %s) has no name, likely unregistered", node.Instance, node.PeerID)
						continue
					}
					networkStatuses[node.PeerID] = status
				} else {
					log.Debugf("Node %s (peer ID: %s) not found in network status response", node.Instance, node.PeerID)
				}
			}
		}

		if len(networkStatuses) == 0 && len(nodes) > 0 {
			log.Warnf("Failed to get network status for any nodes")
			if !m.apiClient.IsConnected() {
				log.Warnf("GraphQL API connection is down. Last error: %v (occurred %s ago)",
					m.apiClient.GetLastError(),
					time.Since(m.apiClient.GetLastErrorTime()).Round(time.Second))
				log.Info("Will continue with local status only and retry connection on next check")
			}
		}
	}

	// Create a map to track which nodes we've seen in this discovery
	discoveredInstances := make(map[string]bool)
	for _, node := range nodes {
		discoveredInstances[node.Instance] = true
	}

	// Prepare all updates
	updates := make(map[string]*NodeStatus)
	unhealthyNodes := make(map[string]string) // instance -> reason

	for _, node := range nodes {
		// Get or create node status
		status := &NodeStatus{
			Instance:    node.Instance, // Set the instance from the discovered node
			PeerID:      node.PeerID,
			Name:        node.Name,
			Version:     node.Version,
			LastChecked: time.Now(),
		}

		// If we have network status for this node, update the status with the network data
		if node.PeerID != "" {
			if networkStatus, ok := networkStatuses[node.PeerID]; ok {
				// Skip nodes where Online status is not set (nil)
				if networkStatus.Online == nil {
					log.Debugf("Skipping node %s: Online status not set", node.PeerID)
					continue
				}

				// Update status with network data
				status.Name = networkStatus.Name
				status.APR = networkStatus.APR
				status.Online = *networkStatus.Online
				status.Jailed = networkStatus.Jailed
				status.JailReason = networkStatus.JailReason
				status.Queries24Hours = networkStatus.Queries24Hours
				status.Uptime24Hours = networkStatus.Uptime24Hours
				status.Version = networkStatus.Version
				status.ServedData24Hours = networkStatus.ServedData24Hours
				
				// Handle *big.Int fields - create new instances to avoid sharing the same reference
				if networkStatus.StoredData != nil {
					status.StoredData = new(big.Int).Set(networkStatus.StoredData)
				}
				if networkStatus.TotalDelegation != nil {
					status.TotalDelegation = new(big.Int).Set(networkStatus.TotalDelegation)
				}
				if networkStatus.ClaimedReward != nil {
					status.ClaimedReward = new(big.Int).Set(networkStatus.ClaimedReward)
				}
				if networkStatus.ClaimableReward != nil {
					status.ClaimableReward = new(big.Int).Set(networkStatus.ClaimableReward)
				}
				
				status.CreatedAt = networkStatus.CreatedAt

				// Set the network status
				if networkStatus.Status != "" {
					status.NetworkStatus = networkStatus.Status
					log.Debugf("Node %s has network status: %s", node.Instance, status.NetworkStatus)
				} else {
					status.NetworkStatus = "active" // Normal registered node
				}
			} else {
				// We have a peer ID but no network status - this is a newly created node
				status.NetworkStatus = "unregistered"
				log.Debugf("Node %s has peer ID %s but no network status, marking as unregistered", node.Instance, status.PeerID)
			}
		}

		// Determine if the node is healthy
		status.Healthy = m.isNodeHealthy(status)
		if !status.Healthy {
			unhealthyNodes[node.Instance] = m.getUnhealthyReason(status)
		}

		updates[node.Instance] = status
	}

	// Update all nodes
	for instance, status := range updates {
		m.nodes[instance] = status
	}

	// Remove nodes that are no longer present
	for instance := range m.nodes {
		if _, exists := discoveredInstances[instance]; !exists {
			delete(m.nodes, instance)
		}
	}

	// Update metrics if exporter is set
	if m.metricsExporter != nil {
		m.metricsExporter.UpdateMetrics()
	}

	return nil
}

// isNodeHealthy determines if a node is healthy based on its status
func (m *Monitor) isNodeHealthy(node *NodeStatus) bool {

	// Special handling for nodes with unregistered network status (newly created nodes)
	if node.NetworkStatus == "unregistered" {
		// For unregistered nodes, only check that they're running locally
		// This gives newly created nodes time to register on the network
		log.Debugf("Node %s has unregistered network status, considering healthy if running locally", node.PeerID)
		return true
	}

	// If node was created within the last 12 hours, consider it healthy regardless of other statuses
	if !node.CreatedAt.IsZero() && time.Since(node.CreatedAt) <= 12*time.Hour {
		log.Debugf("Node %s was created within the last 12 hours, considering healthy during grace period", node.PeerID)
		return true
	}

	// Check network status (only if Online is explicitly set to false)
	if !node.Online {
		return false
	}

	// Check if jailed
	if node.Jailed {
		return false
	}

	// Check APR
	if node.APR <= 0 {
		return false
	}

	return true
}

// getUnhealthyReason returns a human-readable reason why a node is unhealthy
func (m *Monitor) getUnhealthyReason(node *NodeStatus) string {

	if node.NetworkStatus == "unregistered" {
		return "Node is not yet registered on the network"
	}

	if !node.Online {
		return "Node is offline on the network"
	}

	if node.Jailed {
		return fmt.Sprintf("Node is jailed: %s", node.JailReason)
	}

	if node.APR <= 0 {
		return "Node has zero or negative APR"
	}

	return "Unknown reason"
}

// GetNodeStatuses returns a copy of the current node statuses
func (m *Monitor) GetNodeStatuses() map[string]*NodeStatus {
	log.Debug("Starting GetNodeStatuses")

	result := make(map[string]*NodeStatus, len(m.nodes))
	for k, v := range m.nodes {
		// Create a copy of the status to avoid external modification of our internal state
		statusCopy := *v
		result[k] = &statusCopy
	}

	log.Debugf("GetNodeStatuses returning %d nodes", len(result))
	return result
}
