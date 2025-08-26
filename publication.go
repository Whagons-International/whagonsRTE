package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/igm/sockjs-go/v3/sockjs"
	"github.com/lib/pq"
)

// startPublicationListeners starts listeners for all tenant databases
func (e *RealtimeEngine) startPublicationListeners() {
	e.mutex.RLock()
	tenantDBs := make(map[string]*sql.DB)
	for name, db := range e.tenantDBs {
		tenantDBs[name] = db
	}
	e.mutex.RUnlock()

	// We need to get the actual database names for each tenant
	query := "SELECT name, database FROM tenants WHERE database IS NOT NULL"
	rows, err := e.landlordDB.Query(query)
	if err != nil {
		log.Printf("❌ Failed to query tenants for listeners: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var tenantName, dbName string
		if err := rows.Scan(&tenantName, &dbName); err != nil {
			log.Printf("⚠️  Error scanning tenant row for listener: %v", err)
			continue
		}

		if _, exists := tenantDBs[tenantName]; exists {
			go e.listenToTenantPublications(tenantName, dbName)
		}
	}
}

// listenToTenantPublications listens to PostgreSQL notifications for a specific tenant
func (e *RealtimeEngine) listenToTenantPublications(tenantName, dbName string) {
	log.Printf("🎧 Starting publication listener for tenant: %s (database: %s)", tenantName, dbName)

	listener := pq.NewListener(
		fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			config.DBHost, config.DBPort, config.DBUsername, config.DBPassword, dbName),
		10*time.Second,
		time.Minute,
		func(ev pq.ListenerEventType, err error) {
			if err != nil {
				log.Printf("❌ PostgreSQL listener error for %s: %v", tenantName, err)
			}
		})

	defer listener.Close()

	// Discover all NOTIFY channels for this tenant by inspecting triggers
	e.mutex.RLock()
	tenantDB := e.tenantDBs[tenantName]
	e.mutex.RUnlock()
	if tenantDB == nil {
		log.Printf("❌ No tenant DB connection found for %s", tenantName)
		return
	}

	channels, err := discoverNotifyChannels(tenantDB)
	if err != nil {
		log.Printf("❌ Failed to discover notify channels for %s: %v", tenantName, err)
		return
	}
	if len(channels) == 0 {
		log.Printf("⚠️  No notify channels discovered for %s", tenantName)
	}

	// Subscribe to all discovered channels
	for _, ch := range channels {
		if err := listener.Listen(ch); err != nil {
			log.Printf("❌ Failed to listen to channel %s for tenant %s: %v", ch, tenantName, err)
			continue
		}
		log.Printf("✅ Listening to channel '%s' for tenant: %s", ch, tenantName)
	}

	for {
		select {
		case notification := <-listener.Notify:
			if notification != nil {
				e.handlePublicationNotification(tenantName, notification)
			}
		case <-time.After(90 * time.Second):
			// Ping to keep connection alive
			if err := listener.Ping(); err != nil {
				log.Printf("❌ Ping failed for tenant %s: %v", tenantName, err)
				return
			}
		}
	}
}

// discoverNotifyChannels queries the tenant DB for tables with change triggers
// and returns the corresponding NOTIFY channels (whagons_<table>_changes)
func discoverNotifyChannels(db *sql.DB) ([]string, error) {
	const q = `
		SELECT c.relname AS table_name
		FROM pg_trigger t
		JOIN pg_class c ON c.oid = t.tgrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE NOT t.tgisinternal
		  AND t.tgname = c.relname || '_changes_trigger'
		  AND n.nspname = 'public'
		  AND c.relname LIKE 'wh_%'
	`

	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var channels []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			continue
		}
		channels = append(channels, fmt.Sprintf("whagons_%s_changes", table))
	}
	return channels, nil
}

// handlePublicationNotification processes a PostgreSQL notification
func (e *RealtimeEngine) handlePublicationNotification(tenantName string, notification *pq.Notification) {
	log.Printf("📡 Publication notification received from %s on channel '%s'", tenantName, notification.Channel)

	// Parse the PostgreSQL notification payload once
	var pgNotification PostgreSQLNotification
	if err := json.Unmarshal([]byte(notification.Extra), &pgNotification); err != nil {
		log.Printf("❌ Failed to parse notification JSON from %s: %v", tenantName, err)
		return
	}

	// Create generic publication message
	message := PublicationMessage{
		Type:        "database",
		TenantName:  tenantName,
		Table:       pgNotification.Table,
		Operation:   pgNotification.Operation,
		NewData:     pgNotification.NewData,
		OldData:     pgNotification.OldData,
		Message:     fmt.Sprintf("%s on %s", pgNotification.Operation, pgNotification.Table),
		DBTimestamp: pgNotification.Timestamp,
		ClientTime:  time.Now().Format(time.RFC3339),
	}

	log.Printf("🔄 Processed %s operation on %s.%s - broadcasting to sessions",
		pgNotification.Operation, tenantName, pgNotification.Table)

	// Broadcast to all connected SockJS sessions
	e.BroadcastPublicationMessage(message)
}

// getTaskName safely extracts the task name from a TaskRecord
// (removed task-specific helper; messages are table-agnostic)

// BroadcastPublicationMessage sends a publication message to authenticated sessions with tenant access
func (e *RealtimeEngine) BroadcastPublicationMessage(message PublicationMessage) {
	e.mutex.RLock()
	sessions := make(map[string]sockjs.Session)
	authSessions := make(map[string]*AuthenticatedSession)
	for id, session := range e.sessions {
		sessions[id] = session
	}
	for id, authSession := range e.authenticatedSessions {
		authSessions[id] = authSession
	}
	e.mutex.RUnlock()

	broadcastCount := 0
	authorizedCount := 0

	for sessionID, session := range sessions {
		authSession, isAuthenticated := authSessions[sessionID]

		if !isAuthenticated {
			// Skip unauthenticated sessions (shouldn't happen with new auth flow)
			log.Printf("⚠️ Skipping unauthenticated session %s", sessionID)
			continue
		}

		// Check if the authenticated session can access this tenant's data
		if !authSession.canAccessTenant(message.TenantName) {
			log.Printf("🔒 Session %s (tenant: %s) denied access to %s data",
				sessionID, authSession.TenantName, message.TenantName)
			continue
		}

		authorizedCount++

		// Set the sessionId for this specific session
		message.SessionId = sessionID

		jsonMessage, err := json.Marshal(message)
		if err != nil {
			log.Printf("❌ Failed to marshal publication message: %v", err)
			continue
		}

		if err := session.Send(string(jsonMessage)); err != nil {
			log.Printf("❌ Failed to send to session %s: %v", sessionID, err)
			// Remove failed session
			e.mutex.Lock()
			delete(e.sessions, sessionID)
			delete(e.authenticatedSessions, sessionID)
			e.mutex.Unlock()
		} else {
			broadcastCount++
			log.Printf("📤 Sent publication to authenticated session %s (tenant: %s)",
				sessionID, authSession.TenantName)
		}
	}

	if authorizedCount > 0 {
		log.Printf("📡 Broadcasted publication to %d/%d authorized sessions for tenant: %s",
			broadcastCount, authorizedCount, message.TenantName)
	} else {
		log.Printf("📡 No authorized sessions found for tenant: %s", message.TenantName)
	}
}
