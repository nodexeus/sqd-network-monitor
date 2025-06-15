package discovery

import (
	"context"

	"github.com/nodexeus/sqd-network-monitor/pkg/api"
	"github.com/nodexeus/sqd-network-monitor/pkg/monitor"
)

// GraphQLDiscoverer discovers nodes by querying the GraphQL API
type GraphQLDiscoverer struct {
	apiClient *api.GraphQLClient
}

// NewGraphQLDiscoverer creates a new GraphQLDiscoverer
func NewGraphQLDiscoverer(apiClient *api.GraphQLClient) *GraphQLDiscoverer {
	return &GraphQLDiscoverer{
		apiClient: apiClient,
	}
}

// DiscoverNodes implements the Discoverer interface by querying the GraphQL API
func (d *GraphQLDiscoverer) DiscoverNodes(ctx context.Context) ([]*monitor.DiscoveredNode, error) {
	// Get node network statuses from the GraphQL API
	nodeStatuses, err := d.apiClient.GetNodeNetworkStatuses(ctx)
	if err != nil {
		return nil, err
	}

	// Convert NodeNetworkStatus to DiscoveredNode
	nodes := make([]*monitor.DiscoveredNode, 0, len(nodeStatuses))
	for _, status := range nodeStatuses {
		nodes = append(nodes, &monitor.DiscoveredNode{
			Instance: status.PeerID, // Use PeerID as Instance for now
			PeerID:   status.PeerID,
			Name:     status.Name,
			Version:  status.Version,
		})
	}

	return nodes, nil
}
