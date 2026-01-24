package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fasthttp/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period (must be less than pongWait)
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 512 * 1024 // 512KB
)

var deadlinePanicOnce sync.Once

func safeSetReadDeadline(conn *websocket.Conn, t time.Time) {
	defer func() {
		if r := recover(); r != nil {
			deadlinePanicOnce.Do(func() {
				log.Printf("⚠️  Recovered from panic in SetReadDeadline (fasthttp hijackConn). Disabling read deadlines for this process. panic=%v", r)
			})
		}
	}()
	_ = conn.SetReadDeadline(t)
}

func safeSetWriteDeadline(conn *websocket.Conn, t time.Time) {
	defer func() {
		if r := recover(); r != nil {
			deadlinePanicOnce.Do(func() {
				log.Printf("⚠️  Recovered from panic in SetWriteDeadline (fasthttp hijackConn). Disabling write deadlines for this process. panic=%v", r)
			})
		}
	}()
	_ = conn.SetWriteDeadline(t)
}

// websocketHandler handles WebSocket upgrade requests
func (e *RealtimeEngine) websocketHandler(c *fiber.Ctx) error {
	// Get the underlying fasthttp request context
	fctx := c.Context()

	// Extract bearer token and domain from query parameters or headers
	token := extractBearerToken(
		string(fctx.Request.Header.Peek("Authorization")),
		string(fctx.QueryArgs().Peek("token")),
	)
	domain := string(fctx.QueryArgs().Peek("domain"))

	if token == "" {
		log.Printf("❌ No bearer token provided")
		return c.Status(fiber.StatusUnauthorized).SendString("Bearer token required")
	}

	if domain == "" {
		log.Printf("❌ No domain provided")
		return c.Status(fiber.StatusBadRequest).SendString("Domain parameter required")
	}

	// Authenticate the token for the specific domain
	authSession, err := e.authenticateTokenForDomain(token, domain)
	if err != nil {
		log.Printf("❌ Authentication failed (domain: %s): %v", domain, err)
		return c.Status(fiber.StatusUnauthorized).SendString(fmt.Sprintf("Authentication failed for domain %s", domain))
	}

	// Upgrade using a fasthttp-native upgrader (compatible with Fiber/fasthttp).
	// This avoids the gorilla+fasthttp hijack wrapper that was causing nil deref panics.
	if err := e.upgrader.Upgrade(fctx, func(wsConn *websocket.Conn) {
		// Generate session ID
		sessionID := uuid.New().String()

		// Create WebSocket session
		wsSession := &WebSocketSession{
			Conn:     wsConn,
			ID:       sessionID,
			Tenant:   authSession.TenantName,
			UserID:   authSession.UserID,
			LastPing: time.Now(),
		}

		// Set the session ID in the auth session
		authSession.SessionID = sessionID

		// Add to session tracking
		e.mutex.Lock()
		e.sessions[sessionID] = wsSession
		e.authenticatedSessions[sessionID] = authSession
		sessionCount := len(e.sessions)
		e.mutex.Unlock()

		log.Printf("✅ WebSocket session %s connected (domain: %s, tenant: %s, user: %d, total sessions: %d)",
			sessionID, domain, authSession.TenantName, authSession.UserID, sessionCount)

		// Send welcome message
		welcomeMsg := SystemMessage{
			Type:      "system",
			Operation: "authenticated",
			Message:   fmt.Sprintf("Authenticated for domain: %s (tenant: %s)", domain, authSession.TenantName),
			Data: map[string]interface{}{
				"domain":      domain,
				"tenant_name": authSession.TenantName,
				"user_id":     authSession.UserID,
				"abilities":   authSession.Abilities,
			},
			Timestamp: time.Now().Format(time.RFC3339),
			SessionId: sessionID,
		}
		e.sendMessage(wsSession, welcomeMsg)

		// IMPORTANT: With fasthttp hijacked conns, the upgrader expects this handler to
		// own the connection for its entire lifetime. If we return while goroutines
		// are still using wsConn, fasthttp/websocket may reuse internal buffers and
		// the connection wrapper, leading to nil-deref panics in Read/SetReadDeadline.
		//
		// So: keep this handler blocked until the connection is closed.
		go e.writePump(wsSession)
		e.readPump(wsSession)
	}); err != nil {
		log.Printf("❌ WebSocket upgrade failed: %v", err)
		return c.Status(fiber.StatusBadRequest).SendString("WebSocket upgrade failed")
	}

	// Return nil to prevent Fiber from sending a response (WebSocket handles it)
	return nil
}

// readPump handles reading messages from the WebSocket connection
func (e *RealtimeEngine) readPump(wsSession *WebSocketSession) {
	defer func() {
		e.cleanupSession(wsSession.ID, wsSession.Tenant)
		wsSession.Conn.Close()
	}()

	safeSetReadDeadline(wsSession.Conn, time.Now().Add(pongWait))
	wsSession.Conn.SetPongHandler(func(string) error {
		safeSetReadDeadline(wsSession.Conn, time.Now().Add(pongWait))
		wsSession.LastPing = time.Now()
		return nil
	})
	wsSession.Conn.SetReadLimit(maxMessageSize)

	for {
		_, message, err := wsSession.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("❌ WebSocket read error for session %s: %v", wsSession.ID, err)
			}
			break
		}

		log.Printf("📥 WebSocket received message from session %s (tenant: %s): %s",
			wsSession.ID, wsSession.Tenant, string(message))

		// Echo the message back
		var msgData interface{}
		if err := json.Unmarshal(message, &msgData); err != nil {
			msgData = string(message)
		}

		response := SystemMessage{
			Type:      "echo",
			Operation: "echo",
			Message:   fmt.Sprintf("Echo from %s: %s", wsSession.Tenant, string(message)),
			Data:      msgData,
			Timestamp: time.Now().Format(time.RFC3339),
			SessionId: wsSession.ID,
		}

		e.sendMessage(wsSession, response)
	}
}

// writePump handles writing messages to the WebSocket connection
func (e *RealtimeEngine) writePump(wsSession *WebSocketSession) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		wsSession.Conn.Close()
	}()

	for range ticker.C {
		safeSetWriteDeadline(wsSession.Conn, time.Now().Add(writeWait))
		if err := wsSession.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			log.Printf("❌ WebSocket ping error for session %s: %v", wsSession.ID, err)
			return
		}
	}
}

// sendMessage sends a message to a WebSocket session
func (e *RealtimeEngine) sendMessage(wsSession *WebSocketSession, message SystemMessage) error {
	safeSetWriteDeadline(wsSession.Conn, time.Now().Add(writeWait))

	jsonMessage, err := json.Marshal(message)
	if err != nil {
		log.Printf("❌ Failed to marshal message: %v", err)
		return err
	}

	return wsSession.Conn.WriteMessage(websocket.TextMessage, jsonMessage)
}

// BroadcastSystemMessage sends a system message to all connected sessions
func (e *RealtimeEngine) BroadcastSystemMessage(message SystemMessage) {
	e.mutex.RLock()
	sessions := make(map[string]*WebSocketSession)
	for id, session := range e.sessions {
		sessions[id] = session
	}
	e.mutex.RUnlock()

	broadcastCount := 0
	for sessionID, wsSession := range sessions {
		// Set the sessionId for this specific session
		message.SessionId = sessionID

		if err := e.sendMessage(wsSession, message); err != nil {
			log.Printf("❌ Failed to send to session %s: %v", sessionID, err)
			// Remove failed session
			e.mutex.Lock()
			delete(e.sessions, sessionID)
			delete(e.authenticatedSessions, sessionID)
			e.mutex.Unlock()
		} else {
			broadcastCount++
		}
	}

	if broadcastCount > 0 {
		log.Printf("📡 Broadcasted system message to %d sessions", broadcastCount)
	}
}

// getConnectedSessionsCount returns the number of currently connected sessions
func (e *RealtimeEngine) GetConnectedSessionsCount() int {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return len(e.sessions)
}

// getNegotiationSessionsCount returns 0 (no negotiation phase with native WebSockets)
func (e *RealtimeEngine) GetNegotiationSessionsCount() int {
	return 0
}

// getTotalSessionsCount returns the total number of sessions
func (e *RealtimeEngine) GetTotalSessionsCount() int {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return len(e.sessions)
}

// disconnectAllSessions gracefully disconnects all active sessions
func (e *RealtimeEngine) DisconnectAllSessions() {
	e.mutex.Lock()
	sessions := make(map[string]*WebSocketSession)
	for id, session := range e.sessions {
		sessions[id] = session
	}
	e.mutex.Unlock()

	// Send disconnect notification
	disconnectMsg := SystemMessage{
		Type:      "system",
		Operation: "server_shutdown",
		Message:   "Server is shutting down",
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Disconnect all sessions
	for sessionID, wsSession := range sessions {
		disconnectMsg.SessionId = sessionID
		e.sendMessage(wsSession, disconnectMsg)
		wsSession.Conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "Server shutdown"))
		wsSession.Conn.Close()
		log.Printf("📡 Disconnected session: %s", sessionID)
	}

	// Clear all sessions
	e.mutex.Lock()
	e.sessions = make(map[string]*WebSocketSession)
	e.authenticatedSessions = make(map[string]*AuthenticatedSession)
	e.mutex.Unlock()

	log.Printf("📡 All sessions disconnected - %d total", len(sessions))
}

// getTenantDatabasesCount returns the number of connected tenant databases
func (e *RealtimeEngine) GetTenantDatabasesCount() int {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return len(e.tenantDBs)
}

// IsLandlordConnected checks if the landlord database is connected
func (e *RealtimeEngine) IsLandlordConnected() bool {
	return e.landlordDB != nil
}

// BroadcastMessage is a simplified interface for controllers to broadcast messages
func (e *RealtimeEngine) BroadcastMessage(msgType, operation, message string, data interface{}) {
	systemMessage := SystemMessage{
		Type:      msgType,
		Operation: operation,
		Message:   message,
		Data:      data,
		Timestamp: time.Now().Format(time.RFC3339),
		// SessionId will be set per session in BroadcastSystemMessage
	}

	e.BroadcastSystemMessage(systemMessage)
}

// GetCacheStats returns statistics about the token cache
func (e *RealtimeEngine) GetCacheStats() map[string]int {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	totalCached := len(e.tokenCache)
	expiredCount := 0
	now := time.Now()

	for _, cachedToken := range e.tokenCache {
		if now.After(cachedToken.ExpiresAt) {
			expiredCount++
		}
	}

	return map[string]int{
		"total_cached_tokens": totalCached,
		"expired_tokens":      expiredCount,
		"active_tokens":       totalCached - expiredCount,
	}
}

// cleanupSession removes a session from all tracking maps
func (e *RealtimeEngine) cleanupSession(sessionID, tenantName string) {
	e.mutex.Lock()
	delete(e.sessions, sessionID)
	delete(e.authenticatedSessions, sessionID)
	remaining := len(e.sessions)
	e.mutex.Unlock()

	log.Printf("📡 Session %s disconnected (tenant: %s) - %d sessions remaining",
		sessionID, tenantName, remaining)
}

// cleanupZombieSessions removes sessions that are no longer active
func (e *RealtimeEngine) cleanupZombieSessions() {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	var zombieSessions []string

	// Check sessions - if ping fails, mark as zombie
	for sessionID, wsSession := range e.sessions {
		safeSetWriteDeadline(wsSession.Conn, time.Now().Add(writeWait))
		// IMPORTANT: Control frames (Ping/Pong/Close) must have payload <= 125 bytes.
		// Sending JSON here can exceed that limit and causes "websocket: invalid control frame",
		// which incorrectly marks healthy sessions as zombies and deletes them from tracking maps.
		if err := wsSession.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			log.Printf("🧟 Found zombie session: %s (error: %v)", sessionID, err)
			zombieSessions = append(zombieSessions, sessionID)
		}
	}

	// Clean up zombie sessions
	for _, sessionID := range zombieSessions {
		if wsSession, exists := e.sessions[sessionID]; exists {
			wsSession.Conn.Close()
		}
		delete(e.sessions, sessionID)
		delete(e.authenticatedSessions, sessionID)
		log.Printf("🧹 Cleaned up zombie session: %s", sessionID)
	}

	if len(zombieSessions) > 0 {
		log.Printf("🧹 Cleaned up %d zombie sessions - %d remaining",
			len(zombieSessions), len(e.sessions))
	}
}
