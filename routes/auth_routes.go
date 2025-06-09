package routes

import (
	"github.com/bytebeatz/bandroom-auth/controllers"
	"github.com/bytebeatz/bandroom-auth/middlewares"
	"github.com/gin-gonic/gin"
)

// AuthRoutes sets up authentication-related routes
func AuthRoutes(router *gin.Engine) {
	auth := router.Group("/auth")
	{
		auth.POST("/register", controllers.Register) // User Registration
		auth.POST(
			"/login",
			middlewares.RateLimitLogin(),
			controllers.Login,
		) // Apply Rate Limiting to Login
		auth.POST("/logout", controllers.Logout)        // Logout Route
		auth.POST("/refresh", controllers.RefreshToken) // Refresh Token Route
		auth.GET("/validate", controllers.AuthValidate) // Token Validation
	}
}
