# whagonsRLE

A Go implementation of real-time database synchronization using SockJS WebSockets. Built for **whagons** to maintain consistent sync between PostgreSQL tables and IndexedDB data with minimal data transfer for instant frontend querying and rendering.

## 🚀 Installation

### Standard Installation
```bash
GOSUMDB=off go install github.com/suisseworks/whagonsRLE@latest
```


### Using Make Commands
```bash
# Normal installation
make install

# Skip checksum verification
make install-skip-checksum
```

## 📋 What It Does

- **Real-time sync** between PostgreSQL and browser IndexedDB
- **Minimal data transfer** - only sends changes, not full datasets
- **WebSocket-based** communication using SockJS for reliability
- **Instant frontend updates** without manual refreshing
- **Consistent data state** across database and frontend storage
- **Dynamic tenant detection** - automatically connects to new tenants in real-time
- **Event-driven architecture** - uses PostgreSQL LISTEN/NOTIFY for instant updates

## 🚀 Quick Setup

### 1. Environment Variables
Set up your environment variables:
```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_USERNAME=postgres
export DB_PASSWORD=your_password
export DB_LANDLORD=landlord_db_name
export SERVER_PORT=8082
```

### 2. Run the Application
```bash
go run .
```

The application will automatically:
- ✅ Connect to your landlord database
- ✅ Set up PostgreSQL triggers and notification functions
- ✅ Connect to existing tenant databases
- ✅ Start listening for real-time tenant changes

## 🏢 Multi-Tenant Architecture

- **Landlord Database**: Central database containing tenant configurations
- **Tenant Databases**: Individual databases for each tenant's data  
- **Real-time Detection**: New tenants are automatically discovered and connected
- **Smart Retry Logic**: Handles timing issues when databases are created after tenant records
- **Auto-Setup**: PostgreSQL triggers and functions are created automatically on startup
- **API Management**: Manual tenant reload via `POST /api/tenants/reload`

## 🛠 Optional Manual Setup

The `sql/` directory contains scripts for manual setup or debugging:
- `sql/landlord_tenant_notifications.sql` - Manual trigger setup (optional)
- `sql/debug_tenant_notifications.sql` - Debugging queries to verify setup

## 🛠 Built With

- Go 1.24.3
- Fiber v2 (HTTP framework)
- SockJS-Go v3 (WebSocket implementation)
- PostgreSQL driver with LISTEN/NOTIFY support

---

**License:** MIT License - see [LICENSE](LICENSE) file  
**Repository:** [github.com/suisseworks/whagonsRLE](https://github.com/suisseworks/whagonsRLE) 