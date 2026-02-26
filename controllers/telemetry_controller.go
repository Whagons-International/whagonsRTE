package controllers

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// TelemetryController handles telemetry-related endpoints
type TelemetryController struct {
	engine           TelemetryEngineInterface
	superAdminEmails map[string]bool
}

// TelemetryEngineInterface defines the methods we need from RealtimeEngine for telemetry
type TelemetryEngineInterface interface {
	QueryTelemetryErrors(page, perPage int, tenantName, category string, userID int, search, startDate, endDate, sortBy, sortOrder string) (interface{}, error)
	GetTelemetryStats() (interface{}, error)
	AuthenticateAndGetEmail(bearerToken, domain string) (string, error)
	GetSessionsInfo() (interface{}, error)
	GetSessionByID(sessionID string) (interface{}, error)
	SendCommandToSession(sessionID, command, message string, data interface{}) error
	GetTenantsInfo() (interface{}, error)
	GetTenantDetails(tenantName string) (interface{}, error)
	ExecuteReadOnlyQuery(tenantName, query string) (interface{}, error)
	GetDatabaseTables(tenantName string) (interface{}, error)
	GetTableColumns(tenantName, tableName string) (interface{}, error)
	GetTableRows(tenantName, tableName string, page, perPage int, sortBy, sortOrder string) (interface{}, error)
	UpdateTableRow(tenantName, tableName string, primaryKey, updates map[string]interface{}, force bool) error
	DeleteTableRow(tenantName, tableName string, primaryKey map[string]interface{}, force bool) error
	DeleteTenant(tenantID int) (interface{}, error)
}

// TelemetryQueryParams mirrors the main package struct
type TelemetryQueryParams struct {
	Page       int    `json:"page"`
	PerPage    int    `json:"per_page"`
	TenantName string `json:"tenant_name"`
	Category   string `json:"category"`
	UserID     int    `json:"user_id"`
	Search     string `json:"search"`
	StartDate  string `json:"start_date"`
	EndDate    string `json:"end_date"`
	SortBy     string `json:"sort_by"`
	SortOrder  string `json:"sort_order"`
}

// TelemetryQueryResult mirrors the main package struct
type TelemetryQueryResult struct {
	Data       interface{} `json:"data"`
	Total      int         `json:"total"`
	Page       int         `json:"page"`
	PerPage    int         `json:"per_page"`
	TotalPages int         `json:"total_pages"`
}

// TelemetryStats mirrors the main package struct
type TelemetryStats struct {
	TotalErrors   int         `json:"total_errors"`
	ErrorsLast24h int         `json:"errors_last_24h"`
	ErrorsLast7d  int         `json:"errors_last_7d"`
	TopCategories interface{} `json:"top_categories"`
	TopTenants    interface{} `json:"top_tenants"`
}

// NewTelemetryController creates a new telemetry controller
func NewTelemetryController(engine TelemetryEngineInterface) *TelemetryController {
	tc := &TelemetryController{
		engine:           engine,
		superAdminEmails: make(map[string]bool),
	}
	tc.loadSuperAdminsConfig()
	return tc
}

// loadSuperAdminsConfig loads the super admins configuration from YAML file
func (tc *TelemetryController) loadSuperAdminsConfig() {
	// Try multiple possible paths
	possiblePaths := []string{
		"super_admins.yaml",
		"./super_admins.yaml",
		filepath.Join(os.Getenv("PWD"), "super_admins.yaml"),
	}

	var configFile *os.File
	var err error
	var loadedPath string

	for _, path := range possiblePaths {
		configFile, err = os.Open(path)
		if err == nil {
			loadedPath = path
			break
		}
	}

	if err != nil {
		log.Printf("⚠️  super_admins.yaml not found, no super admins configured for telemetry")
		return
	}
	defer configFile.Close()

	// Parse the simple YAML format manually
	scanner := bufio.NewScanner(configFile)
	inEmailsList := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// Check if we're in the emails list
		if strings.HasPrefix(trimmedLine, "emails:") {
			inEmailsList = true
			continue
		}

		// Parse list items (lines starting with "- ")
		if inEmailsList && strings.HasPrefix(trimmedLine, "- ") {
			email := strings.TrimPrefix(trimmedLine, "- ")
			email = strings.TrimSpace(email)
			normalized := strings.ToLower(email)
			tc.superAdminEmails[normalized] = true
		} else if inEmailsList && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inEmailsList = false
		}
	}

	log.Printf("✅ Telemetry controller loaded %d super admin emails from %s", len(tc.superAdminEmails), loadedPath)
}

// isSuperAdmin checks if an email is in the super admin list
func (tc *TelemetryController) isSuperAdmin(email string) bool {
	normalized := strings.ToLower(strings.TrimSpace(email))
	return tc.superAdminEmails[normalized]
}

// requireSuperAdmin validates that the request is from a super admin
func (tc *TelemetryController) requireSuperAdmin(c *fiber.Ctx) (string, error) {
	// Get authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return "", fiber.NewError(fiber.StatusUnauthorized, "Authorization header required")
	}

	// Extract bearer token
	bearerToken := ""
	if strings.HasPrefix(authHeader, "Bearer ") {
		bearerToken = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		return "", fiber.NewError(fiber.StatusUnauthorized, "Invalid authorization format")
	}

	// Get domain from X-Domain header
	domain := c.Get("X-Domain")
	if domain == "" {
		return "", fiber.NewError(fiber.StatusBadRequest, "X-Domain header required")
	}

	// Authenticate the token and get user email
	tokenPreview := bearerToken
	if len(tokenPreview) > 20 {
		tokenPreview = tokenPreview[:20]
	}
	email, err := tc.engine.AuthenticateAndGetEmail(bearerToken, domain)
	if err != nil {
		log.Printf("❌ Authentication failed for telemetry request (domain: %s, token preview: %s...): %v",
			domain, tokenPreview, err)
		// Include more detail in error for debugging (only in dev - in prod you might want to hide this)
		return "", fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
	}

	// Check if user is super admin
	if !tc.isSuperAdmin(email) {
		log.Printf("🚫 Telemetry access denied for: %s", email)
		return "", fiber.NewError(fiber.StatusForbidden, "Access denied - super admin privileges required")
	}

	log.Printf("✅ Telemetry access granted for: %s", email)
	return email, nil
}

// GetErrors retrieves paginated error telemetry
// @Summary Get error telemetry
// @Description Returns paginated error telemetry with filtering and sorting
// @Tags telemetry
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param per_page query int false "Items per page" default(50)
// @Param tenant_name query string false "Filter by tenant name"
// @Param category query string false "Filter by error category"
// @Param user_id query int false "Filter by user ID"
// @Param search query string false "Search in message, email, URL"
// @Param start_date query string false "Start date filter (RFC3339)"
// @Param end_date query string false "End date filter (RFC3339)"
// @Param sort_by query string false "Sort field" default(received_at)
// @Param sort_order query string false "Sort order (asc/desc)" default(desc)
// @Success 200 {object} TelemetryQueryResult
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/errors [get]
func (tc *TelemetryController) GetErrors(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	// Parse query parameters
	page, _ := strconv.Atoi(c.Query("page", "1"))
	perPage, _ := strconv.Atoi(c.Query("per_page", "50"))
	userID, _ := strconv.Atoi(c.Query("user_id", "0"))

	tenantName := c.Query("tenant_name")
	category := c.Query("category")
	search := c.Query("search")
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")
	sortBy := c.Query("sort_by", "received_at")
	sortOrder := c.Query("sort_order", "desc")

	// Query telemetry errors through the engine
	result, err := tc.engine.QueryTelemetryErrors(page, perPage, tenantName, category, userID, search, startDate, endDate, sortBy, sortOrder)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to query errors",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(result)
}

// GetStats retrieves aggregated telemetry statistics
// @Summary Get telemetry statistics
// @Description Returns aggregated error statistics
// @Tags telemetry
// @Accept json
// @Produce json
// @Success 200 {object} TelemetryStats
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/stats [get]
func (tc *TelemetryController) GetStats(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	// Get telemetry stats through the engine
	stats, err := tc.engine.GetTelemetryStats()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to get statistics",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(stats)
}

// GetSessions retrieves active WebSocket sessions
// @Summary Get active sessions
// @Description Returns all active WebSocket sessions with user details
// @Tags telemetry
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/sessions [get]
func (tc *TelemetryController) GetSessions(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	sessions, err := tc.engine.GetSessionsInfo()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to get sessions",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(sessions)
}

// GetTenants retrieves all tenants with connection status
// @Summary Get tenants overview
// @Description Returns all tenants with their database connection status and session counts
// @Tags telemetry
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/tenants [get]
func (tc *TelemetryController) GetTenants(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	tenants, err := tc.engine.GetTenantsInfo()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to get tenants",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(tenants)
}

// GetTenantDetails retrieves detailed information for a specific tenant
// @Summary Get tenant details
// @Description Returns detailed tenant information including stats and active sessions
// @Tags telemetry
// @Accept json
// @Produce json
// @Param tenantName path string true "Tenant name"
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/tenants/{tenantName} [get]
func (tc *TelemetryController) GetTenantDetails(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	tenantName := c.Params("tenantName")
	if tenantName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "tenant name is required",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	details, err := tc.engine.GetTenantDetails(tenantName)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to get tenant details",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(details)
}

// GetSessionDetail retrieves detailed information for a specific session
// @Summary Get session detail
// @Description Returns detailed information for a specific WebSocket session
// @Tags telemetry
// @Accept json
// @Produce json
// @Param sessionId path string true "Session ID"
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/telemetry/sessions/{sessionId} [get]
func (tc *TelemetryController) GetSessionDetail(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	sessionID := c.Params("sessionId")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "session ID is required",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	detail, err := tc.engine.GetSessionByID(sessionID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(detail)
}

// SendSessionCommandRequest represents a request to send a command to a session
type SendSessionCommandRequest struct {
	Command string      `json:"command"`
	Data    interface{} `json:"data,omitempty"`
}

// SendSessionCommand sends a command message to a specific session via WebSocket
// @Summary Send command to session
// @Description Sends a remote command to a specific WebSocket session (e.g., clear_cache, resync)
// @Tags telemetry
// @Accept json
// @Produce json
// @Param sessionId path string true "Session ID"
// @Param request body SendSessionCommandRequest true "Command request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/telemetry/sessions/{sessionId}/command [post]
func (tc *TelemetryController) SendSessionCommand(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	sessionID := c.Params("sessionId")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "session ID is required",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	var req SendSessionCommandRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "Invalid request body",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	if req.Command == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "command field is required",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	// Validate allowed commands
	allowedCommands := map[string]bool{
		"clear_cache":   true,
		"resync":        true,
		"reload":        true,
		"unregister_sw": true,
	}
	if !allowedCommands[req.Command] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   fmt.Sprintf("unknown command: %s. Allowed: clear_cache, resync, reload, unregister_sw", req.Command),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	// Send the command through the engine
	if err := tc.engine.SendCommandToSession(sessionID, req.Command, fmt.Sprintf("Remote command: %s", req.Command), req.Data); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	log.Printf("📡 Sent command '%s' to session %s", req.Command, sessionID)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Command '%s' sent to session %s", req.Command, sessionID),
		"data": fiber.Map{
			"session_id": sessionID,
			"command":    req.Command,
			"timestamp":  time.Now().Format(time.RFC3339),
		},
	})
}

// QueryRequest represents a database query request
type QueryRequest struct {
	TenantName string `json:"tenant_name"`
	Query      string `json:"query"`
}

// TableInfo represents basic table information
type TableInfo struct {
	Name      string `json:"name"`
	Schema    string `json:"schema"`
	RowCount  int64  `json:"row_count"`
	TableType string `json:"table_type"`
}

// ColumnInfo represents column information
type ColumnInfo struct {
	Name         string  `json:"name"`
	DataType     string  `json:"data_type"`
	IsNullable   bool    `json:"is_nullable"`
	DefaultValue *string `json:"default_value"`
	IsPrimaryKey bool    `json:"is_primary_key"`
}

// ExecuteQuery executes a read-only SQL query against a tenant database
// @Summary Execute database query
// @Description Executes a read-only SQL query against a specified tenant database
// @Tags telemetry
// @Accept json
// @Produce json
// @Param request body QueryRequest true "Query request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/query [post]
func (tc *TelemetryController) ExecuteQuery(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	var req QueryRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "Invalid request body",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	if req.TenantName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "tenant_name is required",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	if req.Query == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "query is required",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	result, err := tc.engine.ExecuteReadOnlyQuery(req.TenantName, req.Query)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to execute query",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(result)
}

// GetTables retrieves all tables for a tenant database
// @Summary Get database tables
// @Description Returns list of all tables in a tenant database
// @Tags telemetry
// @Accept json
// @Produce json
// @Param tenant_name query string true "Tenant name"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/tables [get]
func (tc *TelemetryController) GetTables(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	tenantName := c.Query("tenant_name")
	if tenantName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "tenant_name query parameter is required",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	tables, err := tc.engine.GetDatabaseTables(tenantName)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to get tables",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(tables)
}

// GetTableColumns retrieves columns for a specific table
// @Summary Get table columns
// @Description Returns column information for a specific table
// @Tags telemetry
// @Accept json
// @Produce json
// @Param tenant_name query string true "Tenant name"
// @Param table_name query string true "Table name"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/columns [get]
func (tc *TelemetryController) GetTableColumns(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	tenantName := c.Query("tenant_name")
	tableName := c.Query("table_name")

	if tenantName == "" || tableName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "tenant_name and table_name query parameters are required",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	columns, err := tc.engine.GetTableColumns(tenantName, tableName)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to get columns",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(columns)
}

// GetTableRows retrieves rows from a table with pagination
// @Summary Get table rows
// @Description Returns paginated rows from a specific table
// @Tags telemetry
// @Accept json
// @Produce json
// @Param tenant_name query string true "Tenant name"
// @Param table_name query string true "Table name"
// @Param page query int false "Page number" default(1)
// @Param per_page query int false "Rows per page" default(100)
// @Param sort_by query string false "Column to sort by"
// @Param sort_order query string false "Sort order (asc/desc)" default(asc)
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/rows [get]
func (tc *TelemetryController) GetTableRows(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	tenantName := c.Query("tenant_name")
	tableName := c.Query("table_name")

	if tenantName == "" || tableName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "tenant_name and table_name query parameters are required",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	page, _ := strconv.Atoi(c.Query("page", "1"))
	perPage, _ := strconv.Atoi(c.Query("per_page", "100"))
	sortBy := c.Query("sort_by", "")
	sortOrder := c.Query("sort_order", "asc")

	result, err := tc.engine.GetTableRows(tenantName, tableName, page, perPage, sortBy, sortOrder)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to get rows",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(result)
}

// Tech support secret for dangerous operations (hardcoded for now)
const techSupportSecret = "wh@g0ns-t3ch-supp0rt-2024!"

// RowModifyRequest represents a request to update or delete a row
type RowModifyRequest struct {
	TenantName string                 `json:"tenant_name"`
	TableName  string                 `json:"table_name"`
	PrimaryKey map[string]interface{} `json:"primary_key"`
	Updates    map[string]interface{} `json:"updates,omitempty"`
	Secret     string                 `json:"secret"`
	Force      bool                   `json:"force"`
}

// UpdateRow updates a row in a tenant database
// @Summary Update a table row
// @Description Updates a specific row in a tenant database table (requires secret)
// @Tags telemetry
// @Accept json
// @Produce json
// @Param request body RowModifyRequest true "Update request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/row [put]
func (tc *TelemetryController) UpdateRow(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	var req RowModifyRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "Invalid request body",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	// Validate secret
	if req.Secret != techSupportSecret {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":    "error",
			"message":   "Invalid tech support secret",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	if req.TenantName == "" || req.TableName == "" || len(req.PrimaryKey) == 0 || len(req.Updates) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "tenant_name, table_name, primary_key, and updates are required",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	err = tc.engine.UpdateTableRow(req.TenantName, req.TableName, req.PrimaryKey, req.Updates, req.Force)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to update row",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Row updated successfully",
	})
}

// DeleteRow deletes a row from a tenant database
// @Summary Delete a table row
// @Description Deletes a specific row from a tenant database table (requires secret)
// @Tags telemetry
// @Accept json
// @Produce json
// @Param request body RowModifyRequest true "Delete request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/row [delete]
func (tc *TelemetryController) DeleteRow(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	var req RowModifyRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "Invalid request body",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	// Validate secret
	if req.Secret != techSupportSecret {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":    "error",
			"message":   "Invalid tech support secret",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	if req.TenantName == "" || req.TableName == "" || len(req.PrimaryKey) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "tenant_name, table_name, and primary_key are required",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	err = tc.engine.DeleteTableRow(req.TenantName, req.TableName, req.PrimaryKey, req.Force)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to delete row",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Row deleted successfully",
	})
}

// DeleteTenantRequest represents a request to delete an entire tenant
type DeleteTenantRequest struct {
	TenantID int    `json:"tenant_id"`
	Secret   string `json:"secret"`
}

// DeleteTenant drops a tenant database, removes the landlord row, and disconnects.
// Requires super admin access + tech support secret. Uses tenant ID to avoid ambiguity.
// @Summary Delete a tenant
// @Description Drops tenant database, removes landlord row, cleans up mappings (requires secret)
// @Tags telemetry
// @Accept json
// @Produce json
// @Param request body DeleteTenantRequest true "Delete tenant request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/telemetry/tenant [delete]
func (tc *TelemetryController) DeleteTenant(c *fiber.Ctx) error {
	// Require super admin access
	_, err := tc.requireSuperAdmin(c)
	if err != nil {
		fiberErr, ok := err.(*fiber.Error)
		if ok {
			return c.Status(fiberErr.Code).JSON(fiber.Map{
				"status":    "error",
				"message":   fiberErr.Message,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	var req DeleteTenantRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "Invalid request body",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	// Validate secret
	if req.Secret != techSupportSecret {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":    "error",
			"message":   "Invalid tech support secret",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	if req.TenantID <= 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":    "error",
			"message":   "tenant_id is required and must be positive",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	log.Printf("⚠️  [TECH SUPPORT] DELETE TENANT requested: id=%d", req.TenantID)

	result, err := tc.engine.DeleteTenant(req.TenantID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":    "error",
			"message":   "Failed to delete tenant",
			"error":     err.Error(),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "success",
		"message": "Tenant deleted",
		"data":    result,
	})
}
