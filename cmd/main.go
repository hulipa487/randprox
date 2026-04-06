package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"randprox/internal/accounting"
	"randprox/internal/admin"
	"randprox/internal/config"
	"randprox/internal/db"
	"randprox/internal/proxy"
	"randprox/internal/wireguard"
)

func main() {
	// Load config
	configPath := "config.toml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Printf("Config file not found at %s, using defaults\n", configPath)
		cfg = config.DefaultConfig()
	}

	// Initialize database
	database, err := db.New(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Create default admin user
	if err := database.CreateDefaultAdmin(cfg.Admin.DefaultUsername, cfg.Admin.DefaultPassword); err != nil {
		log.Fatalf("Failed to create default admin: %v", err)
	}

	// Initialize traffic accountant
	accountant := accounting.New(database, 30*time.Second)

	// Initialize WireGuard device manager
	deviceMgr := wireguard.NewDeviceManager(10 * time.Minute)

	// Initialize HTTP proxy
	httpProxy := proxy.NewHTTPServer(database, deviceMgr, accountant)

	// Initialize admin API
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	apiHandler := admin.NewAPIHandler(database, deviceMgr)
	apiHandler.SetupRoutes(r)

	// Start proxy in goroutine
	go func() {
		log.Printf("Starting proxy server on %s\n", cfg.Proxy.Bind)
		if err := httpProxy.ListenAndServe("tcp", cfg.Proxy.Bind); err != nil {
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	// Start admin server in goroutine
	go func() {
		log.Printf("Starting admin server on %s\n", cfg.Admin.Bind)
		if err := r.Run(cfg.Admin.Bind); err != nil {
			log.Fatalf("Admin server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")

	// Shutdown components
	if err := accountant.Stop(); err != nil {
		log.Printf("Error stopping accountant: %v", err)
	}
	deviceMgr.Shutdown()

	log.Println("Shutdown complete")
}
