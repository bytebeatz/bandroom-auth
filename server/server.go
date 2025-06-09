package server

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/bytebeatz/bandroom-auth/config"
	"github.com/bytebeatz/bandroom-auth/db"
	"github.com/bytebeatz/bandroom-auth/middlewares"
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

