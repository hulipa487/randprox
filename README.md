# randprox

A multi-user WireGuard HTTP proxy with an admin panel.

## Features

- **HTTP CONNECT Proxy Only**: Focused proxy implementation
- **Per-User Routing**: Each user gets their own isolated WireGuard tunnel
- **Web Admin Panel**: Gin-based API for managing users and their configurations
- **WireGuard Config Upload**: Upload standard WireGuard .conf files per user
- **Dynamic Reloading**: WireGuard devices reload automatically on config changes
- **Per-User Traffic Accounting**: Tracks bytes uploaded/downloaded per user
- **SQLite Database**: Lightweight storage for users, admins, and traffic stats

## Architecture

```
randprox/
├── cmd/
│   └── main.go                     # Main application entry point
├── internal/
│   ├── config/
│   │   └── config.go               # TOML config file parser
│   ├── db/
│   │   ├── models.go               # Database models (User, TrafficStats, Admin)
│   │   └── db.go                   # SQLite database operations via GORM
│   ├── wireguard/
│   │   ├── parser.go               # WireGuard config file parser
│   │   ├── device.go               # Single WireGuard device wrapper
│   │   └── manager.go              # Manages multiple WireGuard devices (per user)
│   ├── proxy/
│   │   └── http.go                 # HTTP CONNECT proxy with authentication
│   ├── accounting/
│   │   └── traffic.go              # Traffic stats accounting (in-memory + DB)
│   └── admin/
│       ├── api.go                  # Gin API handlers
│       ├── auth.go                 # JWT authentication middleware
│       └── embed.go                # Frontend embedding (placeholder)
├── go.mod
├── go.sum
├── config.example.toml
└── README.md
```

## Building

Requires Go 1.25+ and CGO (for SQLite):

```bash
CGO_ENABLED=1 go build -o randprox ./cmd
```

## Configuration

Copy `config.example.toml` to `config.toml` and modify as needed:

```toml
[proxy]
bind = "0.0.0.0:8080"

[admin]
bind = "0.0.0.0:8081"
default_username = "admin"
default_password = "changeMe123!"

[database]
path = "./randprox.db"

[logging]
path = "./randprox.log"
```

## Running

```bash
./randprox [config.toml]
```

Default credentials for the admin panel:
- Username: `admin`
- Password: `changeMe123!`

## Admin API Endpoints

### Authentication
- `POST /api/admin/login` - Admin login

### User Management
- `GET /api/users` - List all users
- `POST /api/users` - Create a new user
- `GET /api/users/:id` - Get a user by ID
- `PUT /api/users/:id` - Update a user
- `DELETE /api/users/:id` - Delete a user
- `POST /api/users/:id/reload` - Reload a user's WireGuard device
- `GET /api/users/:id/stats` - Get traffic stats for a user

### Admin Operations
- `POST /api/admin/change-password` - Change admin password

## Acknowledgements

Forked from and inspired by [wireproxy](https://github.com/octeep/wireproxy).
