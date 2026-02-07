package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
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
