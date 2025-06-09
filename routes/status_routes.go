package routes

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/bytebeatz/bandroom-auth/config"
	"github.com/bytebeatz/bandroom-auth/db"
	"github.com/gin-gonic/gin"
)

// Track service start time
var (
	startTime = time.Now()
	healthy   atomic.Bool // Atomic boolean to store health status
)

func StatusRoutes(router *gin.Engine) {
	router.GET("/status", func(c *gin.Context) {
		// Check database health
		dbStatus := "connected"
		if err := db.DB.Ping(); err != nil {
			dbStatus = "disconnected"
		}

		// Calculate uptime since the service started
		uptime := time.Since(startTime).String()

		// Determine overall service health
		serviceStatus := "healthy"
		if dbStatus == "disconnected" {
			serviceStatus = "unhealthy"
			healthy.Store(false) // Mark service as unhealthy
		} else {
			healthy.Store(true) // Mark service as healthy
		}

		// Return a dynamic JSON response
		c.IndentedJSON(http.StatusOK, gin.H{
			"service":  config.Config.ServiceName, // Read from config
			"status":   serviceStatus,
			"database": dbStatus,
			"uptime":   uptime,
		})
	})
}
