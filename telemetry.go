package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// TelemetryStore handles storing error telemetry data
type TelemetryStore struct {
	db *sql.DB
}

// NewTelemetryStore creates a new telemetry store using the landlord database
func NewTelemetryStore(db *sql.DB) *TelemetryStore {
	return &TelemetryStore{db: db}
}

// EnsureTable creates the error_telemetry table if it doesn't exist
func (ts *TelemetryStore) EnsureTable() error {
	if ts.db == nil {
		return fmt.Errorf("database not connected")
	}

	createTableSQL := `
		CREATE TABLE IF NOT EXISTS error_telemetry (
			id VARCHAR(50) PRIMARY KEY,
			tenant_name VARCHAR(100),
			user_id INTEGER,
			user_uid VARCHAR(100),
			user_email VARCHAR(255),
			category VARCHAR(50),
			message TEXT,
			stack TEXT,
			app_version VARCHAR(20),
			commit_hash VARCHAR(50),
			build_time VARCHAR(50),
			url TEXT,
			user_agent TEXT,
			redux_state JSONB,
			client_timestamp TIMESTAMPTZ,
			received_at TIMESTAMPTZ DEFAULT NOW(),
			session_id VARCHAR(100)
		);

		CREATE INDEX IF NOT EXISTS idx_error_telemetry_tenant ON error_telemetry(tenant_name);
		CREATE INDEX IF NOT EXISTS idx_error_telemetry_user ON error_telemetry(user_id);
		CREATE INDEX IF NOT EXISTS idx_error_telemetry_category ON error_telemetry(category);
		CREATE INDEX IF NOT EXISTS idx_error_telemetry_received ON error_telemetry(received_at);
	`

	if _, err := ts.db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("failed to create error_telemetry table: %w", err)
	}

	log.Println("✅ Error telemetry table ready")
	return nil
}

// StoreError saves an error to the database
func (ts *TelemetryStore) StoreError(errData TelemetryError, tenantName string, sessionID string) error {
	if ts.db == nil {
		return fmt.Errorf("database not connected")
	}

	// Parse client timestamp
	var clientTimestamp *time.Time
	if errData.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, errData.Timestamp); err == nil {
			clientTimestamp = &t
		}
	}

	// Convert redux state to JSON
	var reduxState []byte
	if errData.Context.ReduxStateSnapshot != nil {
		var err error
		reduxState, err = json.Marshal(errData.Context.ReduxStateSnapshot)
		if err != nil {
			reduxState = nil
		}
	}

	insertSQL := `
		INSERT INTO error_telemetry (
			id, tenant_name, user_id, user_uid, user_email, category, message, stack,
			app_version, commit_hash, build_time, url, user_agent, redux_state,
			client_timestamp, session_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (id) DO NOTHING
	`

	_, err := ts.db.Exec(insertSQL,
		errData.ID,
		tenantName,
		nullableInt(errData.Context.UserID),
		nullableString(errData.Context.UserUID),
		nullableString(errData.Context.UserEmail),
		errData.Category,
		errData.Message,
		nullableString(errData.Stack),
		errData.Context.AppVersion,
		errData.Context.CommitHash,
		errData.Context.BuildTime,
		errData.Context.URL,
		errData.Context.UserAgent,
		reduxState,
		clientTimestamp,
		sessionID,
	)

	if err != nil {
		return fmt.Errorf("failed to insert error: %w", err)
	}

	return nil
}

// nullableInt returns nil if the int is 0, otherwise returns the int
func nullableInt(i int) interface{} {
	if i == 0 {
		return nil
	}
	return i
}

// nullableString returns nil if the string is empty, otherwise returns the string
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// handleTelemetryMessage processes incoming telemetry messages
func (e *RealtimeEngine) handleTelemetryMessage(wsSession *WebSocketSession, message []byte) {
	var telemetryMsg TelemetryMessage
	if err := json.Unmarshal(message, &telemetryMsg); err != nil {
		log.Printf("❌ Failed to parse telemetry message: %v", err)
		return
	}

	if telemetryMsg.Operation != "error" {
		log.Printf("⚠️  Unknown telemetry operation: %s", telemetryMsg.Operation)
		return
	}

	// Get tenant name from session
	tenantName := wsSession.Tenant

	// Store the error
	if e.telemetryStore != nil {
		if err := e.telemetryStore.StoreError(telemetryMsg.Data, tenantName, wsSession.ID); err != nil {
			log.Printf("❌ Failed to store telemetry error: %v", err)
			return
		}

		log.Printf("📊 Stored error telemetry: %s (tenant: %s, category: %s)",
			telemetryMsg.Data.ID, tenantName, telemetryMsg.Data.Category)
	} else {
		log.Printf("⚠️  Telemetry store not initialized, error not stored: %s", telemetryMsg.Data.ID)
	}

	// Send ACK back to client
	ackMsg := TelemetryAckMessage{
		Type:      "telemetry",
		Operation: "ack",
		ErrorIDs:  []string{telemetryMsg.Data.ID},
		Timestamp: time.Now().Format(time.RFC3339),
		SessionId: wsSession.ID,
	}

	ackJSON, err := json.Marshal(ackMsg)
	if err != nil {
		log.Printf("❌ Failed to marshal ACK message: %v", err)
		return
	}

	safeSetWriteDeadline(wsSession.Conn, time.Now().Add(writeWait))
	if err := wsSession.Conn.WriteMessage(1, ackJSON); err != nil { // 1 = TextMessage
		log.Printf("❌ Failed to send ACK to session %s: %v", wsSession.ID, err)
	}
}

// TelemetryQueryParams represents the parameters for querying errors
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

// TelemetryQueryResult represents the paginated result
type TelemetryQueryResult struct {
	Data       []TelemetryErrorRow `json:"data"`
	Total      int                 `json:"total"`
	Page       int                 `json:"page"`
	PerPage    int                 `json:"per_page"`
	TotalPages int                 `json:"total_pages"`
}

// TelemetryErrorRow represents a single error row from the database
type TelemetryErrorRow struct {
	ID              string          `json:"id"`
	TenantName      *string         `json:"tenant_name"`
	UserID          *int            `json:"user_id"`
	UserUID         *string         `json:"user_uid"`
	UserEmail       *string         `json:"user_email"`
	Category        string          `json:"category"`
	Message         string          `json:"message"`
	Stack           *string         `json:"stack"`
	AppVersion      string          `json:"app_version"`
	CommitHash      string          `json:"commit_hash"`
	BuildTime       string          `json:"build_time"`
	URL             string          `json:"url"`
	UserAgent       string          `json:"user_agent"`
	ReduxState      json.RawMessage `json:"redux_state"`
	ClientTimestamp *time.Time      `json:"client_timestamp"`
	ReceivedAt      time.Time       `json:"received_at"`
	SessionID       *string         `json:"session_id"`
}

// TelemetryStats represents aggregated statistics
type TelemetryStats struct {
	TotalErrors   int             `json:"total_errors"`
	ErrorsLast24h int             `json:"errors_last_24h"`
	ErrorsLast7d  int             `json:"errors_last_7d"`
	TopCategories []CategoryCount `json:"top_categories"`
	TopTenants    []TenantCount   `json:"top_tenants"`
}

// CategoryCount represents a category with its count
type CategoryCount struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// TenantCount represents a tenant with its count
type TenantCount struct {
	TenantName string `json:"tenant_name"`
	Count      int    `json:"count"`
}

// QueryErrors retrieves errors with pagination and filtering
func (ts *TelemetryStore) QueryErrors(params TelemetryQueryParams) (*TelemetryQueryResult, error) {
	if ts.db == nil {
		return nil, fmt.Errorf("database not connected")
	}

	// Set defaults
	if params.Page < 1 {
		params.Page = 1
	}
	if params.PerPage < 1 || params.PerPage > 100 {
		params.PerPage = 50
	}
	if params.SortBy == "" {
		params.SortBy = "received_at"
	}
	if params.SortOrder == "" {
		params.SortOrder = "desc"
	}

	// Validate sort_by to prevent SQL injection
	validSortColumns := map[string]bool{
		"received_at": true,
		"tenant_name": true,
		"category":    true,
		"user_email":  true,
		"app_version": true,
		"message":     true,
	}
	if !validSortColumns[params.SortBy] {
		params.SortBy = "received_at"
	}

	// Validate sort_order
	if params.SortOrder != "asc" && params.SortOrder != "desc" {
		params.SortOrder = "desc"
	}

	// Build WHERE clause
	whereConditions := []string{}
	args := []interface{}{}
	argIndex := 1

	if params.TenantName != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("tenant_name = $%d", argIndex))
		args = append(args, params.TenantName)
		argIndex++
	}

	if params.Category != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("category = $%d", argIndex))
		args = append(args, params.Category)
		argIndex++
	}

	if params.UserID > 0 {
		whereConditions = append(whereConditions, fmt.Sprintf("user_id = $%d", argIndex))
		args = append(args, params.UserID)
		argIndex++
	}

	if params.Search != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("(message ILIKE $%d OR user_email ILIKE $%d OR url ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, "%"+params.Search+"%")
		argIndex++
	}

	if params.StartDate != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("received_at >= $%d", argIndex))
		args = append(args, params.StartDate)
		argIndex++
	}

	if params.EndDate != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("received_at <= $%d", argIndex))
		args = append(args, params.EndDate)
		argIndex++
	}

	whereClause := ""
	if len(whereConditions) > 0 {
		whereClause = "WHERE " + strings.Join(whereConditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM error_telemetry %s", whereClause)
	var total int
	if err := ts.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count errors: %w", err)
	}

	// Calculate pagination
	offset := (params.Page - 1) * params.PerPage
	totalPages := (total + params.PerPage - 1) / params.PerPage

	// Query errors
	query := fmt.Sprintf(`
		SELECT id, tenant_name, user_id, user_uid, user_email, category, message, stack,
		       app_version, commit_hash, build_time, url, user_agent, redux_state,
		       client_timestamp, received_at, session_id
		FROM error_telemetry
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, params.SortBy, params.SortOrder, argIndex, argIndex+1)

	args = append(args, params.PerPage, offset)

	rows, err := ts.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query errors: %w", err)
	}
	defer rows.Close()

	errors := []TelemetryErrorRow{}
	for rows.Next() {
		var e TelemetryErrorRow
		var reduxState []byte
		var clientTimestamp sql.NullTime

		err := rows.Scan(
			&e.ID, &e.TenantName, &e.UserID, &e.UserUID, &e.UserEmail,
			&e.Category, &e.Message, &e.Stack, &e.AppVersion, &e.CommitHash,
			&e.BuildTime, &e.URL, &e.UserAgent, &reduxState,
			&clientTimestamp, &e.ReceivedAt, &e.SessionID,
		)
		if err != nil {
			log.Printf("⚠️ Error scanning row: %v", err)
			continue
		}

		if len(reduxState) > 0 {
			e.ReduxState = json.RawMessage(reduxState)
		}
		if clientTimestamp.Valid {
			e.ClientTimestamp = &clientTimestamp.Time
		}

		errors = append(errors, e)
	}

	return &TelemetryQueryResult{
		Data:       errors,
		Total:      total,
		Page:       params.Page,
		PerPage:    params.PerPage,
		TotalPages: totalPages,
	}, nil
}

// GetStats retrieves aggregated telemetry statistics
func (ts *TelemetryStore) GetStats() (*TelemetryStats, error) {
	if ts.db == nil {
		return nil, fmt.Errorf("database not connected")
	}

	stats := &TelemetryStats{}

	// Total errors
	if err := ts.db.QueryRow("SELECT COUNT(*) FROM error_telemetry").Scan(&stats.TotalErrors); err != nil {
		return nil, fmt.Errorf("failed to count total errors: %w", err)
	}

	// Errors in last 24 hours
	if err := ts.db.QueryRow("SELECT COUNT(*) FROM error_telemetry WHERE received_at >= NOW() - INTERVAL '24 hours'").Scan(&stats.ErrorsLast24h); err != nil {
		return nil, fmt.Errorf("failed to count 24h errors: %w", err)
	}

	// Errors in last 7 days
	if err := ts.db.QueryRow("SELECT COUNT(*) FROM error_telemetry WHERE received_at >= NOW() - INTERVAL '7 days'").Scan(&stats.ErrorsLast7d); err != nil {
		return nil, fmt.Errorf("failed to count 7d errors: %w", err)
	}

	// Top categories
	categoryRows, err := ts.db.Query(`
		SELECT category, COUNT(*) as count 
		FROM error_telemetry 
		GROUP BY category 
		ORDER BY count DESC 
		LIMIT 10
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to get top categories: %w", err)
	}
	defer categoryRows.Close()

	for categoryRows.Next() {
		var c CategoryCount
		if err := categoryRows.Scan(&c.Category, &c.Count); err != nil {
			continue
		}
		stats.TopCategories = append(stats.TopCategories, c)
	}

	// Top tenants
	tenantRows, err := ts.db.Query(`
		SELECT COALESCE(tenant_name, 'unknown') as tenant_name, COUNT(*) as count 
		FROM error_telemetry 
		GROUP BY tenant_name 
		ORDER BY count DESC 
		LIMIT 10
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to get top tenants: %w", err)
	}
	defer tenantRows.Close()

	for tenantRows.Next() {
		var t TenantCount
		if err := tenantRows.Scan(&t.TenantName, &t.Count); err != nil {
			continue
		}
		stats.TopTenants = append(stats.TopTenants, t)
	}

	return stats, nil
}
