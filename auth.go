package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// authenticateToken validates a Laravel Sanctum bearer token for a specific tenant domain
func (e *RealtimeEngine) authenticateTokenForDomain(bearerToken, domain string) (*AuthenticatedSession, error) {
	// Check cache first
	if cachedAuth := e.getCachedToken(bearerToken, domain); cachedAuth != nil {
		log.Printf("✅ Using cached authentication for domain: %s", domain)
		// Create a copy with new session ID (will be set by caller)
		return &AuthenticatedSession{
			TenantName: cachedAuth.TenantName,
			UserID:     cachedAuth.UserID,
			TokenID:    cachedAuth.TokenID,
			Abilities:  cachedAuth.Abilities,
			ExpiresAt:  cachedAuth.ExpiresAt,
			LastUsedAt: time.Now(),
		}, nil
	}

	// Cache miss - authenticate against database
	log.Printf("🔍 Cache miss - authenticating against database for domain: %s", domain)
	authSession, err := e.authenticateTokenForDomainDB(bearerToken, domain)
	if err != nil {
		return nil, err
	}

	// Cache the successful authentication
	e.cacheToken(bearerToken, domain, authSession)

	return authSession, nil
}

// authenticateTokenForDomainDB performs the actual database authentication (renamed from original)
func (e *RealtimeEngine) authenticateTokenForDomainDB(bearerToken, domain string) (*AuthenticatedSession, error) {
	// First, look up the tenant information from the landlord database
	tenantInfo, err := e.getTenantByDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("tenant not found for domain %s: %w", domain, err)
	}

	log.Printf("🔍 Found tenant '%s' with database '%s' for domain: %s", tenantInfo.Name, tenantInfo.Database, domain)

	// Get the tenant database connection (connect on-demand if not yet discovered)
	connectLock := e.getTenantConnectLock(tenantInfo.Name)
	connectLock.Lock()
	defer connectLock.Unlock()

	e.mutex.RLock()
	tenantDB, exists := e.tenantDBs[tenantInfo.Name]
	e.mutex.RUnlock()

	if !exists {
		log.Printf("⚠️  Tenant DB not connected yet for %s (domain: %s). Connecting on-demand...", tenantInfo.Name, domain)

		// A tenant row can exist before the tenant DB is ready. Retry a few times with backoff.
		const maxRetries = 5
		baseDelay := 200 * time.Millisecond
		var lastErr error

		for attempt := 1; attempt <= maxRetries; attempt++ {
			if err := e.connectToTenant(*tenantInfo); err != nil {
				lastErr = err
				if attempt == maxRetries {
					break
				}
				delay := time.Duration(attempt) * baseDelay
				log.Printf("⏱️  On-demand tenant connect failed for %s (attempt %d/%d). Retrying in %v... (error: %v)",
					tenantInfo.Name, attempt, maxRetries, delay, err)
				time.Sleep(delay)
				continue
			}

			// Connected successfully: start the publication listener for this tenant (exactly once).
			e.startPublicationListenerOnce(tenantInfo.Name, tenantInfo.Database)

			lastErr = nil
			break
		}

		if lastErr != nil {
			return nil, fmt.Errorf("failed to connect to tenant database for %s: %w", tenantInfo.Name, lastErr)
		}

		// Re-fetch the connected DB handle
		e.mutex.RLock()
		tenantDB, exists = e.tenantDBs[tenantInfo.Name]
		e.mutex.RUnlock()
		if !exists || tenantDB == nil {
			return nil, fmt.Errorf("tenant database connection still not available for tenant: %s", tenantInfo.Name)
		}

		log.Printf("✅ On-demand tenant DB connected for %s (domain: %s)", tenantInfo.Name, domain)
	}

	// Parse Laravel Sanctum token format: {token_id}|{plain_text_token}
	tokenParts := strings.Split(bearerToken, "|")
	if len(tokenParts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	tokenID, err := strconv.Atoi(tokenParts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token ID: %w", err)
	}

	plainTextToken := tokenParts[1]

	// Hash the plain text token (Laravel uses SHA-256)
	hasher := sha256.New()
	hasher.Write([]byte(plainTextToken))
	hashedToken := hex.EncodeToString(hasher.Sum(nil))

	log.Printf("🔍 Authenticating token ID %d for tenant %s with hash: %s", tokenID, tenantInfo.Name, hashedToken[:16]+"...")

	// Validate the token in the specific tenant database
	authSession, err := e.validateTokenInTenant(tenantInfo.Name, tenantDB, tokenID, hashedToken)
	if err != nil {
		return nil, fmt.Errorf("authentication failed for tenant %s: %w", tenantInfo.Name, err)
	}

	log.Printf("✅ Token authenticated for domain %s, tenant: %s, user: %d", domain, tenantInfo.Name, authSession.UserID)
	return authSession, nil
}

// getTenantByDomain looks up tenant information by domain in the landlord database
func (e *RealtimeEngine) getTenantByDomain(domain string) (*TenantDB, error) {
	query := "SELECT name, domain, database FROM tenants WHERE domain = $1 AND database IS NOT NULL"

	var tenant TenantDB
	err := e.landlordDB.QueryRow(query, domain).Scan(&tenant.Name, &tenant.Domain, &tenant.Database)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no tenant found for domain: %s", domain)
		}
		return nil, fmt.Errorf("database error looking up tenant: %w", err)
	}

	return &tenant, nil
}

// Legacy function for backwards compatibility - now deprecated
func (e *RealtimeEngine) authenticateToken(bearerToken string) (*AuthenticatedSession, error) {
	return nil, fmt.Errorf("authenticateToken is deprecated - use authenticateTokenForDomain instead")
}

// validateTokenInTenant checks if a token exists and is valid in a specific tenant database
func (e *RealtimeEngine) validateTokenInTenant(tenantName string, db *sql.DB, tokenID int, hashedToken string) (*AuthenticatedSession, error) {
	query := `
		SELECT id, tokenable_type, tokenable_id, name, token, abilities, 
		       last_used_at, expires_at, created_at, updated_at
		FROM personal_access_tokens 
		WHERE id = $1 AND token = $2
	`

	var token PersonalAccessToken
	var lastUsedAt, expiresAt sql.NullTime

	err := db.QueryRow(query, tokenID, hashedToken).Scan(
		&token.ID,
		&token.TokenableType,
		&token.TokenableID,
		&token.Name,
		&token.Token,
		&token.Abilities,
		&lastUsedAt,
		&expiresAt,
		&token.CreatedAt,
		&token.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("token not found in tenant %s", tenantName)
		}
		return nil, fmt.Errorf("database error in tenant %s: %w", tenantName, err)
	}

	// Convert nullable times
	if lastUsedAt.Valid {
		token.LastUsedAt = &lastUsedAt.Time
	}
	if expiresAt.Valid {
		token.ExpiresAt = &expiresAt.Time
	}

	// Check if token is expired
	if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	// Update last_used_at timestamp
	_, err = db.Exec("UPDATE personal_access_tokens SET last_used_at = $1 WHERE id = $2", time.Now(), tokenID)
	if err != nil {
		log.Printf("⚠️ Failed to update last_used_at for token %d: %v", tokenID, err)
	}

	// Parse abilities (Laravel stores as JSON array)
	abilities := []string{}
	if token.Abilities != "" {
		// Simple parsing for ["*"] or ["ability1", "ability2"]
		cleanAbilities := strings.Trim(token.Abilities, `[]"`)
		if cleanAbilities != "" {
			abilities = strings.Split(strings.ReplaceAll(cleanAbilities, `"`, ""), ",")
		}
	}

	return &AuthenticatedSession{
		TenantName: tenantName,
		UserID:     token.TokenableID,
		TokenID:    token.ID,
		Abilities:  abilities,
		ExpiresAt:  token.ExpiresAt,
		LastUsedAt: time.Now(),
	}, nil
}

// hasAbility checks if the authenticated session has a specific ability
func (auth *AuthenticatedSession) hasAbility(ability string) bool {
	for _, a := range auth.Abilities {
		if a == "*" || a == ability {
			return true
		}
	}
	return false
}

// canAccessTenant checks if the session can access a specific tenant's data
func (auth *AuthenticatedSession) canAccessTenant(tenantName string) bool {
	// User can only access their own tenant
	return auth.TenantName == tenantName
}

// extractBearerToken extracts the bearer token from various sources
func extractBearerToken(authHeader, queryParam string) string {
	// Try Authorization header first
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	// Try query parameter as fallback (for WebSocket connections)
	if queryParam != "" {
		return queryParam
	}

	return ""
}

// getCachedToken retrieves a cached authentication result
func (e *RealtimeEngine) getCachedToken(bearerToken, domain string) *AuthenticatedSession {
	// Create cache key from token hash + domain
	hasher := sha256.New()
	hasher.Write([]byte(bearerToken + ":" + domain))
	cacheKey := hex.EncodeToString(hasher.Sum(nil))

	e.mutex.RLock()
	cachedToken, exists := e.tokenCache[cacheKey]
	e.mutex.RUnlock()

	if !exists {
		return nil
	}

	// Check if cache entry is expired
	if time.Now().After(cachedToken.ExpiresAt) {
		// Remove expired entry
		e.mutex.Lock()
		delete(e.tokenCache, cacheKey)
		e.mutex.Unlock()
		return nil
	}

	return cachedToken.AuthSession
}

// cacheToken stores a successful authentication result
func (e *RealtimeEngine) cacheToken(bearerToken, domain string, authSession *AuthenticatedSession) {
	// Create cache key from token hash + domain
	hasher := sha256.New()
	hasher.Write([]byte(bearerToken + ":" + domain))
	cacheKey := hex.EncodeToString(hasher.Sum(nil))

	// Cache for 15 minutes or until token expires (whichever is sooner)
	cacheExpiry := time.Now().Add(15 * time.Minute)
	if authSession.ExpiresAt != nil && authSession.ExpiresAt.Before(cacheExpiry) {
		cacheExpiry = *authSession.ExpiresAt
	}

	cachedToken := &CachedToken{
		AuthSession: authSession,
		ExpiresAt:   cacheExpiry,
		Domain:      domain,
	}

	e.mutex.Lock()
	e.tokenCache[cacheKey] = cachedToken
	e.mutex.Unlock()

	log.Printf("💾 Cached token for domain %s (expires: %s)", domain, cacheExpiry.Format(time.RFC3339))
}

// cleanupExpiredTokens removes expired tokens from cache (call periodically)
func (e *RealtimeEngine) cleanupExpiredTokens() {
	now := time.Now()

	e.mutex.Lock()
	var expiredKeys []string
	for key, cachedToken := range e.tokenCache {
		if now.After(cachedToken.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(e.tokenCache, key)
	}
	e.mutex.Unlock()

	if len(expiredKeys) > 0 {
		log.Printf("🧹 Cleaned up %d expired cached tokens", len(expiredKeys))
	}
}

// AuthenticateAndGetEmail authenticates a token and returns the user's email
// This combines token authentication with email lookup in one call
func (e *RealtimeEngine) AuthenticateAndGetEmail(bearerToken, domain string) (string, error) {
	authSession, err := e.authenticateTokenForDomain(bearerToken, domain)
	if err != nil {
		return "", err
	}

	// Get user email from tenant database
	e.mutex.RLock()
	tenantDB, exists := e.tenantDBs[authSession.TenantName]
	e.mutex.RUnlock()

	if !exists || tenantDB == nil {
		return "", fmt.Errorf("tenant database not found: %s", authSession.TenantName)
	}

	var email string
	err = tenantDB.QueryRow("SELECT email FROM wh_users WHERE id = $1", authSession.UserID).Scan(&email)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("user not found: %d", authSession.UserID)
		}
		return "", fmt.Errorf("database error: %w", err)
	}

	return email, nil
}

// GetTelemetryStore returns the telemetry store instance
func (e *RealtimeEngine) GetTelemetryStore() *TelemetryStore {
	return e.telemetryStore
}

// QueryTelemetryErrors wraps the telemetry store query method for the controller interface
func (e *RealtimeEngine) QueryTelemetryErrors(page, perPage int, tenantName, category string, userID int, search, startDate, endDate, sortBy, sortOrder string) (interface{}, error) {
	if e.telemetryStore == nil {
		return nil, fmt.Errorf("telemetry store not available")
	}

	params := TelemetryQueryParams{
		Page:       page,
		PerPage:    perPage,
		TenantName: tenantName,
		Category:   category,
		UserID:     userID,
		Search:     search,
		StartDate:  startDate,
		EndDate:    endDate,
		SortBy:     sortBy,
		SortOrder:  sortOrder,
	}

	return e.telemetryStore.QueryErrors(params)
}

// GetTelemetryStats wraps the telemetry store stats method for the controller interface
func (e *RealtimeEngine) GetTelemetryStats() (interface{}, error) {
	if e.telemetryStore == nil {
		return nil, fmt.Errorf("telemetry store not available")
	}

	return e.telemetryStore.GetStats()
}

// SessionInfo represents session info for the API response
type SessionInfo struct {
	SessionID   string `json:"session_id"`
	TenantName  string `json:"tenant_name"`
	UserID      int    `json:"user_id"`
	UserEmail   string `json:"user_email"`
	ConnectedAt string `json:"connected_at"`
	LastPing    string `json:"last_ping"`
}

// SessionsResponse represents the sessions API response
type SessionsResponse struct {
	Sessions []SessionInfo  `json:"sessions"`
	Total    int            `json:"total"`
	ByTenant map[string]int `json:"by_tenant"`
}

// GetSessionsInfo returns information about all active WebSocket sessions
func (e *RealtimeEngine) GetSessionsInfo() (interface{}, error) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	sessions := make([]SessionInfo, 0, len(e.sessions))
	byTenant := make(map[string]int)

	for sessionID, wsSession := range e.sessions {
		// Try to get user email from tenant DB
		email := ""
		if tenantDB, exists := e.tenantDBs[wsSession.Tenant]; exists && tenantDB != nil {
			_ = tenantDB.QueryRow("SELECT email FROM wh_users WHERE id = $1", wsSession.UserID).Scan(&email)
		}

		// Get auth session for more details
		authSession := e.authenticatedSessions[sessionID]
		connectedAt := ""
		if authSession != nil {
			connectedAt = authSession.LastUsedAt.Format(time.RFC3339)
		}

		sessions = append(sessions, SessionInfo{
			SessionID:   sessionID,
			TenantName:  wsSession.Tenant,
			UserID:      wsSession.UserID,
			UserEmail:   email,
			ConnectedAt: connectedAt,
			LastPing:    wsSession.LastPing.Format(time.RFC3339),
		})

		byTenant[wsSession.Tenant]++
	}

	return &SessionsResponse{
		Sessions: sessions,
		Total:    len(sessions),
		ByTenant: byTenant,
	}, nil
}

// TenantInfo represents tenant info for the API response
type TenantInfo struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Domain         string `json:"domain"`
	Database       string `json:"database"`
	Connected      bool   `json:"connected"`
	ActiveSessions int    `json:"active_sessions"`
}

// TenantsResponse represents the tenants API response
type TenantsResponse struct {
	Tenants   []TenantInfo `json:"tenants"`
	Total     int          `json:"total"`
	Connected int          `json:"connected"`
}

// LandlordTenantName is the special tenant name used to access the landlord database
const LandlordTenantName = "__landlord__"

// getDBForTenant returns the *sql.DB for a given tenant name.
// If tenantName is LandlordTenantName, it returns the landlord DB.
func (e *RealtimeEngine) getDBForTenant(tenantName string) (*sql.DB, bool) {
	if tenantName == LandlordTenantName {
		return e.landlordDB, e.landlordDB != nil
	}
	e.mutex.RLock()
	db, exists := e.tenantDBs[tenantName]
	e.mutex.RUnlock()
	return db, exists && db != nil
}

// GetTenantsInfo returns information about all tenants
func (e *RealtimeEngine) GetTenantsInfo() (interface{}, error) {
	if e.landlordDB == nil {
		return nil, fmt.Errorf("landlord database not connected")
	}

	// Query all tenants from landlord
	rows, err := e.landlordDB.Query("SELECT id, name, domain, database FROM tenants WHERE database IS NOT NULL ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("failed to query tenants: %w", err)
	}
	defer rows.Close()

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	// Count sessions per tenant
	sessionsByTenant := make(map[string]int)
	for _, wsSession := range e.sessions {
		sessionsByTenant[wsSession.Tenant]++
	}

	// Always include landlord DB as the first entry
	tenants := []TenantInfo{
		{
			ID:             0,
			Name:           LandlordTenantName,
			Domain:         "landlord",
			Database:       config.DBLandlord,
			Connected:      true,
			ActiveSessions: 0,
		},
	}
	connectedCount := 1 // landlord is always connected

	for rows.Next() {
		var t TenantInfo
		if err := rows.Scan(&t.ID, &t.Name, &t.Domain, &t.Database); err != nil {
			continue
		}

		// Check if we're connected to this tenant
		_, connected := e.tenantDBs[t.Name]
		t.Connected = connected
		if connected {
			connectedCount++
		}

		t.ActiveSessions = sessionsByTenant[t.Name]
		tenants = append(tenants, t)
	}

	return &TenantsResponse{
		Tenants:   tenants,
		Total:     len(tenants),
		Connected: connectedCount,
	}, nil
}

// TenantStats represents statistics for a tenant
type TenantStats struct {
	TotalUsers      int `json:"total_users"`
	ActiveUsers     int `json:"active_users"`
	TotalTasks      int `json:"total_tasks"`
	TotalWorkspaces int `json:"total_workspaces"`
	TotalCategories int `json:"total_categories"`
	TotalTeams      int `json:"total_teams"`
}

// TenantDetails represents detailed information about a tenant
type TenantDetails struct {
	ID             int           `json:"id"`
	Name           string        `json:"name"`
	Domain         string        `json:"domain"`
	Database       string        `json:"database"`
	Connected      bool          `json:"connected"`
	ActiveSessions int           `json:"active_sessions"`
	Stats          TenantStats   `json:"stats"`
	RecentErrors   int           `json:"recent_errors"`
	Sessions       []SessionInfo `json:"sessions"`
}

// GetTenantDetails returns detailed information about a specific tenant
func (e *RealtimeEngine) GetTenantDetails(tenantName string) (interface{}, error) {
	if e.landlordDB == nil {
		return nil, fmt.Errorf("landlord database not connected")
	}

	// Get basic tenant info from landlord
	var details TenantDetails
	err := e.landlordDB.QueryRow(
		"SELECT id, name, domain, database FROM tenants WHERE name = $1 AND database IS NOT NULL",
		tenantName,
	).Scan(&details.ID, &details.Name, &details.Domain, &details.Database)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %s", tenantName)
	}

	e.mutex.RLock()
	tenantDB, connected := e.tenantDBs[tenantName]

	// Get sessions for this tenant
	sessions := []SessionInfo{}
	for sessionID, wsSession := range e.sessions {
		if wsSession.Tenant == tenantName {
			// Try to get user email from tenant DB
			email := ""
			if tenantDB != nil {
				_ = tenantDB.QueryRow("SELECT email FROM wh_users WHERE id = $1", wsSession.UserID).Scan(&email)
			}

			// Get auth session for connected_at
			authSession := e.authenticatedSessions[sessionID]
			connectedAt := ""
			if authSession != nil {
				connectedAt = authSession.LastUsedAt.Format(time.RFC3339)
			}

			sessions = append(sessions, SessionInfo{
				SessionID:   sessionID,
				TenantName:  wsSession.Tenant,
				UserID:      wsSession.UserID,
				UserEmail:   email,
				ConnectedAt: connectedAt,
				LastPing:    wsSession.LastPing.Format(time.RFC3339),
			})
		}
	}
	e.mutex.RUnlock()

	details.Connected = connected
	details.ActiveSessions = len(sessions)
	details.Sessions = sessions

	// Get stats from tenant database if connected
	if connected && tenantDB != nil {
		// Count users
		tenantDB.QueryRow("SELECT COUNT(*) FROM wh_users").Scan(&details.Stats.TotalUsers)

		// Count active users (users with activity in last 30 days based on updated_at)
		tenantDB.QueryRow("SELECT COUNT(*) FROM wh_users WHERE updated_at >= NOW() - INTERVAL '30 days'").Scan(&details.Stats.ActiveUsers)

		// Count tasks
		tenantDB.QueryRow("SELECT COUNT(*) FROM wh_tasks").Scan(&details.Stats.TotalTasks)

		// Count workspaces
		tenantDB.QueryRow("SELECT COUNT(*) FROM wh_workspaces").Scan(&details.Stats.TotalWorkspaces)

		// Count categories
		tenantDB.QueryRow("SELECT COUNT(*) FROM wh_categories").Scan(&details.Stats.TotalCategories)

		// Count teams
		tenantDB.QueryRow("SELECT COUNT(*) FROM wh_teams").Scan(&details.Stats.TotalTeams)
	}

	// Count recent errors from telemetry (last 24h)
	if e.telemetryStore != nil && e.telemetryStore.db != nil {
		e.telemetryStore.db.QueryRow(
			"SELECT COUNT(*) FROM error_telemetry WHERE tenant_name = $1 AND received_at >= NOW() - INTERVAL '24 hours'",
			tenantName,
		).Scan(&details.RecentErrors)
	}

	return &details, nil
}

// DbQueryResult represents a database query result
type DbQueryResult struct {
	Columns         []string                 `json:"columns"`
	Rows            []map[string]interface{} `json:"rows"`
	RowCount        int                      `json:"row_count"`
	ExecutionTimeMs float64                  `json:"execution_time_ms"`
}

// containsSQLKeyword checks if a keyword appears as a standalone SQL keyword
// (not as part of a column/table name like "updated_at" containing "UPDATE")
func containsSQLKeyword(query, keyword string) bool {
	idx := 0
	for {
		pos := strings.Index(query[idx:], keyword)
		if pos < 0 {
			return false
		}
		pos += idx
		// Check character before the keyword
		if pos > 0 {
			before := query[pos-1]
			if isIdentChar(before) {
				idx = pos + len(keyword)
				continue
			}
		}
		// Check character after the keyword
		end := pos + len(keyword)
		if end < len(query) {
			after := query[end]
			if isIdentChar(after) {
				idx = pos + len(keyword)
				continue
			}
		}
		return true
	}
}

// isIdentChar returns true if the byte is a valid SQL identifier character
func isIdentChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}

// ExecuteReadOnlyQuery executes a read-only SQL query against a tenant database
func (e *RealtimeEngine) ExecuteReadOnlyQuery(tenantName, query string) (interface{}, error) {
	tenantDB, exists := e.getDBForTenant(tenantName)

	if !exists || tenantDB == nil {
		return nil, fmt.Errorf("tenant database not connected: %s", tenantName)
	}

	// Basic safety check - only allow SELECT statements
	normalizedQuery := strings.TrimSpace(strings.ToUpper(query))
	if !strings.HasPrefix(normalizedQuery, "SELECT") &&
		!strings.HasPrefix(normalizedQuery, "WITH") &&
		!strings.HasPrefix(normalizedQuery, "EXPLAIN") {
		return nil, fmt.Errorf("only SELECT/WITH/EXPLAIN queries are allowed")
	}

	// Disallow dangerous keywords (as standalone SQL statements, not as part of column names)
	dangerousKeywords := []string{"INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE", "GRANT", "REVOKE"}
	for _, keyword := range dangerousKeywords {
		if containsSQLKeyword(normalizedQuery, keyword) {
			return nil, fmt.Errorf("query contains forbidden keyword: %s", keyword)
		}
	}

	start := time.Now()

	rows, err := tenantDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}

	// Prepare result
	result := &DbQueryResult{
		Columns: columns,
		Rows:    []map[string]interface{}{},
	}

	// Read rows (limit to 1000 for safety)
	rowCount := 0
	maxRows := 1000

	for rows.Next() && rowCount < maxRows {
		// Create a slice of interface{} to hold the values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		// Convert to map
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			// Convert byte slices to strings for JSON
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}

		result.Rows = append(result.Rows, row)
		rowCount++
	}

	result.RowCount = rowCount
	result.ExecutionTimeMs = float64(time.Since(start).Microseconds()) / 1000.0

	return result, nil
}

// TableInfo represents information about a database table
type TableInfo struct {
	Name      string `json:"name"`
	Schema    string `json:"schema"`
	RowCount  int64  `json:"row_count"`
	TableType string `json:"table_type"`
}

// TablesResponse represents the response for GetDatabaseTables
type TablesResponse struct {
	Tables []TableInfo `json:"tables"`
	Total  int         `json:"total"`
}

// GetDatabaseTables returns all tables in a tenant database
func (e *RealtimeEngine) GetDatabaseTables(tenantName string) (interface{}, error) {
	tenantDB, exists := e.getDBForTenant(tenantName)

	if !exists || tenantDB == nil {
		return nil, fmt.Errorf("tenant database not connected: %s", tenantName)
	}

	// Query tables from pg_tables (public schema only for tenant DBs)
	query := `
		SELECT 
			t.tablename as name,
			t.schemaname as schema,
			COALESCE(s.n_live_tup, 0) as row_count,
			'table' as table_type
		FROM pg_tables t
		LEFT JOIN pg_stat_user_tables s ON t.tablename = s.relname AND t.schemaname = s.schemaname
		WHERE t.schemaname = 'public'
		ORDER BY t.tablename
	`

	rows, err := tenantDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	tables := []TableInfo{}
	for rows.Next() {
		var t TableInfo
		if err := rows.Scan(&t.Name, &t.Schema, &t.RowCount, &t.TableType); err != nil {
			continue
		}
		tables = append(tables, t)
	}

	return &TablesResponse{
		Tables: tables,
		Total:  len(tables),
	}, nil
}

// ColumnInfo represents information about a table column
type ColumnInfo struct {
	Name         string  `json:"name"`
	DataType     string  `json:"data_type"`
	IsNullable   bool    `json:"is_nullable"`
	DefaultValue *string `json:"default_value"`
	IsPrimaryKey bool    `json:"is_primary_key"`
	OrdinalPos   int     `json:"ordinal_position"`
}

// ColumnsResponse represents the response for GetTableColumns
type ColumnsResponse struct {
	Columns   []ColumnInfo `json:"columns"`
	TableName string       `json:"table_name"`
	Total     int          `json:"total"`
}

// GetTableColumns returns column information for a specific table
func (e *RealtimeEngine) GetTableColumns(tenantName, tableName string) (interface{}, error) {
	tenantDB, exists := e.getDBForTenant(tenantName)

	if !exists || tenantDB == nil {
		return nil, fmt.Errorf("tenant database not connected: %s", tenantName)
	}

	// Validate table name to prevent SQL injection
	if !isValidIdentifier(tableName) {
		return nil, fmt.Errorf("invalid table name: %s", tableName)
	}

	// Query columns from information_schema
	query := `
		SELECT 
			c.column_name,
			c.data_type,
			c.is_nullable = 'YES' as is_nullable,
			c.column_default,
			COALESCE(
				(SELECT true FROM information_schema.table_constraints tc
				 JOIN information_schema.key_column_usage kcu 
				 ON tc.constraint_name = kcu.constraint_name
				 WHERE tc.table_name = c.table_name 
				 AND tc.constraint_type = 'PRIMARY KEY'
				 AND kcu.column_name = c.column_name
				 LIMIT 1), false
			) as is_primary_key,
			c.ordinal_position
		FROM information_schema.columns c
		WHERE c.table_schema = 'public' AND c.table_name = $1
		ORDER BY c.ordinal_position
	`

	rows, err := tenantDB.Query(query, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to query columns: %w", err)
	}
	defer rows.Close()

	columns := []ColumnInfo{}
	for rows.Next() {
		var col ColumnInfo
		var defaultValue sql.NullString
		if err := rows.Scan(&col.Name, &col.DataType, &col.IsNullable, &defaultValue, &col.IsPrimaryKey, &col.OrdinalPos); err != nil {
			continue
		}
		if defaultValue.Valid {
			col.DefaultValue = &defaultValue.String
		}
		columns = append(columns, col)
	}

	return &ColumnsResponse{
		Columns:   columns,
		TableName: tableName,
		Total:     len(columns),
	}, nil
}

// RowsResponse represents the response for GetTableRows
type RowsResponse struct {
	Rows       []map[string]interface{} `json:"rows"`
	Columns    []string                 `json:"columns"`
	Total      int64                    `json:"total"`
	Page       int                      `json:"page"`
	PerPage    int                      `json:"per_page"`
	TotalPages int                      `json:"total_pages"`
	TableName  string                   `json:"table_name"`
}

// GetTableRows returns paginated rows from a specific table
func (e *RealtimeEngine) GetTableRows(tenantName, tableName string, page, perPage int, sortBy, sortOrder string) (interface{}, error) {
	tenantDB, exists := e.getDBForTenant(tenantName)

	if !exists || tenantDB == nil {
		return nil, fmt.Errorf("tenant database not connected: %s", tenantName)
	}

	// Validate table name to prevent SQL injection
	if !isValidIdentifier(tableName) {
		return nil, fmt.Errorf("invalid table name: %s", tableName)
	}

	// Validate and sanitize sort parameters
	if sortBy != "" && !isValidIdentifier(sortBy) {
		return nil, fmt.Errorf("invalid sort column: %s", sortBy)
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "asc"
	}

	// Default pagination
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 1000 {
		perPage = 100
	}

	// Get total count
	var total int64
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)
	if err := tenantDB.QueryRow(countQuery).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count rows: %w", err)
	}

	// Calculate pagination
	offset := (page - 1) * perPage
	totalPages := int((total + int64(perPage) - 1) / int64(perPage))

	// Build query with optional sorting
	query := fmt.Sprintf("SELECT * FROM %s", tableName)
	if sortBy != "" {
		query += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)
	}
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", perPage, offset)

	rows, err := tenantDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query rows: %w", err)
	}
	defer rows.Close()

	// Get column names
	columnNames, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}

	// Read rows
	resultRows := []map[string]interface{}{}
	for rows.Next() {
		values := make([]interface{}, len(columnNames))
		valuePtrs := make([]interface{}, len(columnNames))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		row := make(map[string]interface{})
		for i, col := range columnNames {
			val := values[i]
			// Convert byte slices to strings for JSON
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		resultRows = append(resultRows, row)
	}

	return &RowsResponse{
		Rows:       resultRows,
		Columns:    columnNames,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
		TableName:  tableName,
	}, nil
}

// DeleteTenantResult holds the outcome of each step during tenant deletion
type DeleteTenantResult struct {
	TenantID     int      `json:"tenant_id"`
	TenantName   string   `json:"tenant_name"`
	DatabaseName string   `json:"database_name"`
	DBDropped    bool     `json:"db_dropped"`
	RowDeleted   bool     `json:"row_deleted"`
	Disconnected bool     `json:"disconnected"`
	Errors       []string `json:"errors,omitempty"`
}

// DeleteTenant drops the tenant database, removes the row from the landlord tenants table,
// and disconnects the in-memory DB pool. Works by tenant ID to avoid ambiguity with duplicate names.
func (e *RealtimeEngine) DeleteTenant(tenantID int) (interface{}, error) {
	if e.landlordDB == nil {
		return nil, fmt.Errorf("landlord database not connected")
	}

	// 1. Look up tenant by ID from landlord
	var name, domain, database string
	err := e.landlordDB.QueryRow(
		"SELECT name, domain, database FROM tenants WHERE id = $1", tenantID,
	).Scan(&name, &domain, &database)
	if err != nil {
		return nil, fmt.Errorf("tenant with id %d not found: %w", tenantID, err)
	}

	result := &DeleteTenantResult{
		TenantID:     tenantID,
		TenantName:   name,
		DatabaseName: database,
	}

	log.Printf("⚠️  [TECH SUPPORT] Deleting tenant id=%d name=%s db=%s", tenantID, name, database)

	// 2. Disconnect the in-memory pool first (stop new queries)
	e.mutex.Lock()
	if db, exists := e.tenantDBs[name]; exists {
		if err := db.Close(); err != nil {
			log.Printf("⚠️  Error closing tenant DB pool %s: %v", name, err)
			result.Errors = append(result.Errors, fmt.Sprintf("close pool: %v", err))
		}
		delete(e.tenantDBs, name)
		result.Disconnected = true
		log.Printf("🔌 Disconnected tenant pool: %s", name)
	} else {
		result.Disconnected = true // wasn't connected, that's fine
	}
	e.mutex.Unlock()

	// 3. Terminate active connections and drop the database
	if database != "" && isValidIdentifier(database) {
		// Terminate all active connections to the tenant DB
		_, _ = e.landlordDB.Exec(
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
			database,
		)

		_, err := e.landlordDB.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS \"%s\"", database))
		if err != nil {
			log.Printf("⚠️  Failed to drop database %s: %v", database, err)
			result.Errors = append(result.Errors, fmt.Sprintf("drop db: %v", err))
		} else {
			result.DBDropped = true
			log.Printf("🗑️  Dropped database: %s", database)
		}
	}

	// 4. Delete the tenant row from landlord (by ID, so only this one row)
	res, err := e.landlordDB.Exec("DELETE FROM tenants WHERE id = $1", tenantID)
	if err != nil {
		log.Printf("⚠️  Failed to delete tenant row id=%d: %v", tenantID, err)
		result.Errors = append(result.Errors, fmt.Sprintf("delete row: %v", err))
	} else {
		rowsAffected, _ := res.RowsAffected()
		result.RowDeleted = rowsAffected > 0
		log.Printf("✅ Deleted tenant row id=%d (rows affected: %d)", tenantID, rowsAffected)
	}

	// 5. Also clean up user-tenant mappings
	// tenant_domain_prefix is the first segment of the domain (e.g., "acme" from "acme.whagons.com")
	domainPrefix := domain
	if dotIdx := strings.Index(domain, "."); dotIdx > 0 {
		domainPrefix = domain[:dotIdx]
	}
	_, mapErr := e.landlordDB.Exec("DELETE FROM tenant_map WHERE tenant_domain_prefix = $1", domainPrefix)
	if mapErr != nil {
		log.Printf("⚠️  Failed to clean up tenant_map for %s (prefix: %s): %v", name, domainPrefix, mapErr)
		result.Errors = append(result.Errors, fmt.Sprintf("clean tenant_map: %v", mapErr))
	}

	if len(result.Errors) > 0 {
		log.Printf("⚠️  [TECH SUPPORT] Tenant deletion completed with errors: %v", result.Errors)
	} else {
		log.Printf("✅ [TECH SUPPORT] Tenant deleted successfully: id=%d name=%s", tenantID, name)
	}

	return result, nil
}

// isValidIdentifier checks if a string is a valid SQL identifier (table/column name)
func isValidIdentifier(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	// Only allow alphanumeric and underscore, must start with letter or underscore
	for i, r := range name {
		if i == 0 {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
				return false
			}
		} else {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
				return false
			}
		}
	}
	return true
}

// UpdateTableRow updates a row in a tenant database
func (e *RealtimeEngine) UpdateTableRow(tenantName, tableName string, primaryKey, updates map[string]interface{}, force bool) error {
	tenantDB, exists := e.getDBForTenant(tenantName)

	if !exists || tenantDB == nil {
		return fmt.Errorf("tenant database not connected: %s", tenantName)
	}

	// Validate table name
	if !isValidIdentifier(tableName) {
		return fmt.Errorf("invalid table name: %s", tableName)
	}

	// Validate all column names in primary key and updates
	for col := range primaryKey {
		if !isValidIdentifier(col) {
			return fmt.Errorf("invalid column name in primary key: %s", col)
		}
	}
	for col := range updates {
		if !isValidIdentifier(col) {
			return fmt.Errorf("invalid column name in updates: %s", col)
		}
	}

	// Build UPDATE query
	setClauses := []string{}
	whereClause := []string{}
	args := []interface{}{}
	argIndex := 1

	for col, val := range updates {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", col, argIndex))
		args = append(args, val)
		argIndex++
	}

	for col, val := range primaryKey {
		whereClause = append(whereClause, fmt.Sprintf("%s = $%d", col, argIndex))
		args = append(args, val)
		argIndex++
	}

	query := fmt.Sprintf("UPDATE %s SET %s WHERE %s",
		tableName,
		strings.Join(setClauses, ", "),
		strings.Join(whereClause, " AND "),
	)

	log.Printf("⚠️ [TECH SUPPORT] Executing UPDATE on %s.%s: %s", tenantName, tableName, query)

	result, err := tenantDB.Exec(query, args...)
	if err != nil {
		// Check for foreign key violation
		if strings.Contains(err.Error(), "foreign key") && !force {
			return fmt.Errorf("foreign key constraint violation - enable 'force' to bypass: %w", err)
		}
		return fmt.Errorf("update failed: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	log.Printf("✅ [TECH SUPPORT] UPDATE affected %d rows", rowsAffected)

	if rowsAffected == 0 {
		return fmt.Errorf("no rows matched the primary key")
	}

	return nil
}

// DeleteTableRow deletes a row from a tenant database
func (e *RealtimeEngine) DeleteTableRow(tenantName, tableName string, primaryKey map[string]interface{}, force bool) error {
	tenantDB, exists := e.getDBForTenant(tenantName)

	if !exists || tenantDB == nil {
		return fmt.Errorf("tenant database not connected: %s", tenantName)
	}

	// Validate table name
	if !isValidIdentifier(tableName) {
		return fmt.Errorf("invalid table name: %s", tableName)
	}

	// Validate all column names in primary key
	for col := range primaryKey {
		if !isValidIdentifier(col) {
			return fmt.Errorf("invalid column name in primary key: %s", col)
		}
	}

	// Build DELETE query
	whereClause := []string{}
	args := []interface{}{}
	argIndex := 1

	for col, val := range primaryKey {
		whereClause = append(whereClause, fmt.Sprintf("%s = $%d", col, argIndex))
		args = append(args, val)
		argIndex++
	}

	// If force is enabled, temporarily disable triggers to bypass foreign key constraints
	if force {
		// Disable triggers for this session
		_, err := tenantDB.Exec("SET session_replication_role = replica")
		if err != nil {
			log.Printf("⚠️ [TECH SUPPORT] Failed to disable triggers: %v", err)
		}
		defer func() {
			// Re-enable triggers
			_, err := tenantDB.Exec("SET session_replication_role = DEFAULT")
			if err != nil {
				log.Printf("⚠️ [TECH SUPPORT] Failed to re-enable triggers: %v", err)
			}
		}()
	}

	query := fmt.Sprintf("DELETE FROM %s WHERE %s",
		tableName,
		strings.Join(whereClause, " AND "),
	)

	log.Printf("⚠️ [TECH SUPPORT] Executing DELETE on %s.%s: %s (force=%v)", tenantName, tableName, query, force)

	result, err := tenantDB.Exec(query, args...)
	if err != nil {
		// Check for foreign key violation
		if strings.Contains(err.Error(), "foreign key") || strings.Contains(err.Error(), "violates") {
			return fmt.Errorf("foreign key constraint violation - enable 'force' to bypass constraints: %w", err)
		}
		return fmt.Errorf("delete failed: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	log.Printf("✅ [TECH SUPPORT] DELETE affected %d rows", rowsAffected)

	if rowsAffected == 0 {
		return fmt.Errorf("no rows matched the primary key")
	}

	return nil
}
