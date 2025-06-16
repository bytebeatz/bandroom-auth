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
		// Core authentication
		auth.POST("/register", controllers.Register) // User Registration
		auth.POST(
			"/login",
			middlewares.RateLimitLogin(),
			controllers.Login,
		) // Login with Rate Limiting
		auth.POST("/logout", controllers.Logout)        // Logout user
		auth.POST("/refresh", controllers.RefreshToken) // Refresh Access Token
		auth.GET("/validate", controllers.AuthValidate) // Validate JWT

		// Email verification
		auth.POST("/send-verification", controllers.SendVerificationEmail) // Send token link
		auth.GET(
			"/verify",
			controllers.VerifyEmailToken,
		) // Accept verification link
	}
}

