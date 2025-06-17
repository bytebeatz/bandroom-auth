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
		auth.POST("/refresh", controllers.RefreshToken) // Refresh token
		auth.GET(
			"/validate",
			controllers.AuthValidate,
		) // Validate access token

		// Email verification
		auth.POST(
			"/resend-verification",
			controllers.ResendVerificationEmail,
		) // Re-send email if not verified
		auth.GET(
			"/verify",
			controllers.VerifyEmailToken,
		) // Handle email verification link

		// Soft delete account
		auth.DELETE(
			"/delete",
			middlewares.AuthMiddleware(),
			controllers.DeleteAccount,
		) // Soft delete user account
	}
}

