package server

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bytebeatz/bandroom-auth/config"
	"github.com/bytebeatz/bandroom-auth/db"
	"github.com/bytebeatz/bandroom-auth/middlewares"
	"github.com/bytebeatz/bandroom-auth/repository"
	"github.com/bytebeatz/bandroom-auth/routes"

	"github.com/gin-gonic/gin"
)

// Start bootstraps and runs the auth server
func Start() error {
	// Load env and config
	config.LoadConfig()

	// Connect to DB
	db.ConnectDatabase()
	defer db.CloseDatabase()

	// Setup Gin router
	router := gin.Default()
	router.Use(middlewares.CORSMiddleware())
	router.Use(gin.Recovery())

	// Register routes
	routes.AuthRoutes(router)
	routes.StatusRoutes(router)

	// 🔁 Start background cleanup job
	go startCleanupWorker()

	// Determine port
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	// Start server in goroutine
	go func() {
		log.Println("🚀 Auth server running on port:", port)
		if err := router.Run(":" + port); err != nil {
			log.Fatalf("❌ Failed to start server: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down auth server gracefully...")
	return nil
}

// startCleanupWorker purges users soft-deleted more than 30 days ago
func startCleanupWorker() {
	ticker := time.NewTicker(24 * time.Hour)
	//ticker := time.NewTicker(10 * time.Second)

	log.Println("🧹 Cleanup worker started. Running every 24 hours.")

	for range ticker.C {
		log.Println("⏳ Checking for expired soft-deleted users...")
		if err := repository.PurgeDeletedUsers(); err != nil {
			log.Println("❌ Error during user purge:", err)
		} else {
			log.Println("✅ Purged soft-deleted users older than 30 days")
		}
	}
}

