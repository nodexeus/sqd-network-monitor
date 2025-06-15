package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nodexeus/sqd-network-monitor/pkg/config"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

// NodeNetworkStatus represents the network status of a node from the GraphQL API
type NodeNetworkStatus struct {
	PeerID            string  `json:"peerId"`
	Name              string  `json:"name"`
	APR               float64 `json:"apr"`
	Online            bool    `json:"online"`
	Jailed            bool    `json:"jailed"`
	JailReason        string  `json:"jailReason"`
	Queries24Hours    int64   `json:"queries24Hours"`
	Uptime24Hours     int64   `json:"uptime24Hours"`
	Version           string  `json:"version"`
	ServedData24Hours int64   `json:"servedData24Hours"`
	StoredData        int64   `json:"storedData"`
	TotalDelegation   int64   `json:"totalDelegation"`
	ClaimedReward     int64   `json:"claimedReward"`
	ClaimableReward   int64   `json:"claimableReward"`
	// Status is used for tracking special states like "pending" for newly created nodes
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

// GraphQLMetricsExporter defines the interface for exporting GraphQL metrics
type GraphQLMetricsExporter interface {
	RecordGraphQLQueryDuration(operation string, duration time.Duration)
	SetGraphQLWorkersReturned(operation string, count int)
	IncGraphQLQueryErrors(operation string, errorType string)
}

// GraphQLClient is a client for the SQD GraphQL API
type GraphQLClient struct {
	config        *config.Config
	httpClient    *http.Client
	metrics       GraphQLMetricsExporter
	lastError     error
	lastErrorTime time.Time
	connected     bool
}

// NewGraphQLClient creates a new GraphQL client
func NewGraphQLClient(cfg *config.Config, metrics GraphQLMetricsExporter) *GraphQLClient {
	client := &GraphQLClient{
		config:     cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		connected:  false,
	}
	
	// Only set metrics if not nil to avoid nil pointer dereference
	if metrics != nil {
		client.metrics = metrics
	}
	
	return client
}

// SetMetricsExporter sets or updates the metrics exporter for the GraphQL client
func (c *GraphQLClient) SetMetricsExporter(metrics GraphQLMetricsExporter) {
	c.metrics = metrics
}

// GraphQLRequest represents a GraphQL request
type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLError represents a GraphQL error
type GraphQLError struct {
	Message string `json:"message"`
}

// GraphQLResponse represents the structure of a GraphQL response
type GraphQLResponse struct {
	Data   map[string]interface{} `json:"data"`
	Errors []GraphQLError         `json:"errors,omitempty"`
}

// GetNodeNetworkStatuses gets the network status of all workers
func (c *GraphQLClient) GetNodeNetworkStatuses(ctx context.Context) ([]*NodeNetworkStatus, error) {
	startTime := time.Now()
	const functionName = "GetNodeNetworkStatuses"

	query := `
	query GetNodeNetworkStatuses {
		workers {
			apr
			name
			online
			jailed
			jailReason
			peerId
			queries24Hours
			uptime24Hours
			version
			servedData24Hours
			storedData
			totalDelegation
			claimedReward
			claimableReward
			createdAt
		}
	}
	`

	// Create the request
	reqBody, err := json.Marshal(GraphQLRequest{
		Query: query,
	})
	if err != nil {
		c.recordError(functionName, fmt.Errorf("error marshaling GraphQL request: %w", err))
		return nil, fmt.Errorf("error marshaling GraphQL request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.config.GraphQL.Endpoint,
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		c.recordError(functionName, fmt.Errorf("error creating HTTP request: %w", err))
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Execute and time the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.recordError(functionName, fmt.Errorf("error executing GraphQL request: %w", err))
		return nil, fmt.Errorf("error executing GraphQL request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
		c.recordError(functionName, err)
		return nil, err
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("error reading response body: %w", err)
		c.recordError(functionName, err)
		return nil, err
	}

	// Parse the response
	var graphQLResp GraphQLResponse
	if err := json.Unmarshal(body, &graphQLResp); err != nil {
		err = fmt.Errorf("error parsing GraphQL response: %w", err)
		c.recordError(functionName, err)
		return nil, err
	}

	// Check for GraphQL errors
	if len(graphQLResp.Errors) > 0 {
		err := fmt.Errorf("GraphQL error: %s", graphQLResp.Errors[0].Message)
		c.recordError(functionName, err)
		return nil, err
	}

	// Extract workers data from response
	workersData, ok := graphQLResp.Data["workers"].([]interface{})
	if !ok {
		errMsg := "invalid response format: workers data not found or not an array"
		c.recordError(functionName, fmt.Errorf(errMsg))
		return nil, fmt.Errorf(errMsg)
	}

	// Convert to NodeNetworkStatus objects
	var statuses []*NodeNetworkStatus
	for _, workerData := range workersData {
		worker, ok := workerData.(map[string]interface{})
		if !ok {
			log.Warn("invalid worker data format, skipping")
			continue
		}

		status, err := c.parseWorkerStatus(worker)
		if err != nil {
			log.Warnf("error parsing worker status: %v, skipping", err)
			continue
		}
		statuses = append(statuses, status)
	}

	// Record success metrics
	duration := time.Since(startTime).Seconds()
	c.recordSuccess(functionName, duration, len(statuses))

	if len(statuses) == 0 {
		return nil, fmt.Errorf("no valid worker statuses found")
	}

	return statuses, nil
}

// TestConnection tests the connection to the GraphQL endpoint
// Returns true if the connection is successful
func (c *GraphQLClient) TestConnection(ctx context.Context) bool {
	// A simple introspection query to test the connection
	query := `{ __schema { queryType { name } } }`

	// Create the request
	reqBody, err := json.Marshal(GraphQLRequest{
		Query: query,
	})
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.config.GraphQL.Endpoint,
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		c.lastError = fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// Parse the response
	var graphQLResp GraphQLResponse
	if err := json.Unmarshal(body, &graphQLResp); err != nil {
		c.lastError = err
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// Check for GraphQL errors
	if len(graphQLResp.Errors) > 0 {
		c.lastError = fmt.Errorf("GraphQL error: %s", graphQLResp.Errors[0].Message)
		c.lastErrorTime = time.Now()
		c.connected = false
		return false
	}

	// If we got here, the connection is working
	c.lastError = nil
	c.lastErrorTime = time.Time{}
	c.connected = true
	return true
}

// GetConnectionStatus returns the current connection status
func (c *GraphQLClient) GetConnectionStatus() (bool, error, time.Time) {
	return c.connected, c.lastError, c.lastErrorTime
}

// IsConnected returns whether the client is currently connected
func (c *GraphQLClient) IsConnected() bool {
	return c.connected
}

// GetLastError returns the last error encountered
func (c *GraphQLClient) GetLastError() error {
	return c.lastError
}

// GetLastErrorTime returns the time of the last error
func (c *GraphQLClient) GetLastErrorTime() time.Time {
	return c.lastErrorTime
}

// recordError records an error that occurred during a GraphQL operation
func (c *GraphQLClient) recordError(functionName string, err error) {
	c.lastError = err
	c.lastErrorTime = time.Now()
	c.connected = false

	// Categorize the error
	errType := "unknown"
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "context deadline exceeded") || strings.Contains(err.Error(), "timeout"):
			errType = "timeout"
		case strings.Contains(err.Error(), "connection refused"):
			errType = "connection_refused"
		case strings.Contains(err.Error(), "no such host"):
			errType = "unknown_host"
		case strings.Contains(err.Error(), "unexpected status code"):
			errType = "http_error"
		case strings.Contains(err.Error(), "unmarshal"):
			errType = "parse_error"
		default:
			errType = "graphql"
		}
	}

	// Log the error with context
	log.WithFields(logrus.Fields{
		"function":  functionName,
		"error_type": errType,
	}).Errorf("GraphQL operation failed: %v", err)

	// Record error in metrics if metrics are enabled
	if c.metrics != nil {
		c.metrics.IncGraphQLQueryErrors(functionName, errType)
	}
}

// recordSuccess records a successful GraphQL operation
func (c *GraphQLClient) recordSuccess(functionName string, duration float64, numWorkers int) {
	c.lastError = nil
	c.lastErrorTime = time.Time{}
	c.connected = true
	log.Debugf("%s completed in %.2f seconds with %d workers", functionName, duration, numWorkers)

	// Record metrics if metrics are enabled and not nil
	if c.metrics != nil {
		// Record the duration and worker count
		c.metrics.RecordGraphQLQueryDuration(functionName, time.Duration(duration*float64(time.Second)))
		c.metrics.SetGraphQLWorkersReturned(functionName, numWorkers)
	}
}

// parseWorkerStatus parses a worker's status from the raw GraphQL response
func (c *GraphQLClient) parseWorkerStatus(worker map[string]interface{}) (*NodeNetworkStatus, error) {
	status := &NodeNetworkStatus{}

	// Required fields
	peerID, ok := worker["peerId"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid peerId")
	}
	status.PeerID = peerID

	// Optional fields with type conversion and error handling
	if name, ok := worker["name"].(string); ok {
		status.Name = name
	}

	if online, ok := worker["online"].(bool); ok {
		status.Online = online
	}

	if jailed, ok := worker["jailed"].(bool); ok {
		status.Jailed = jailed
	}

	if jailReason, ok := worker["jailReason"].(string); ok {
		status.JailReason = jailReason
	}

	if version, ok := worker["version"].(string); ok {
		status.Version = version
	}

	// Parse numeric fields
	if apr, ok := worker["apr"].(float64); ok {
		status.APR = apr
	}

	// Parse string numbers to int64
	for field, ptr := range map[string]*int64{
		"queries24Hours":    &status.Queries24Hours,
		"uptime24Hours":     &status.Uptime24Hours,
		"servedData24Hours": &status.ServedData24Hours,
		"storedData":        &status.StoredData,
		"totalDelegation":   &status.TotalDelegation,
		"claimedReward":     &status.ClaimedReward,
		"claimableReward":   &status.ClaimableReward,
	} {
		if val, ok := worker[field].(string); ok {
			if intVal, err := strconv.ParseInt(val, 10, 64); err == nil {
				*ptr = intVal
			}
		}
	}

	// Parse createdAt time
	if createdAt, ok := worker["createdAt"].(string); ok {
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			status.CreatedAt = t
		}
	}

	return status, nil
}
