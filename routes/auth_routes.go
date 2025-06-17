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
		auth.POST("/login", middlewares.RateLimitLogin(), controllers.Login)
		auth.POST("/logout", controllers.Logout)
		auth.POST("/refresh", controllers.RefreshToken)
		auth.GET("/validate", controllers.AuthValidate)

		// Email verification
		auth.POST("/resend-verification", controllers.ResendVerificationEmail)
		auth.GET("/verify", controllers.VerifyEmailToken)

		// Password reset
		auth.POST("/forgot-password", controllers.RequestPasswordReset) // Send reset token
		auth.POST("/reset-password", controllers.ResetPassword)         // Handle reset flow

		// Soft delete account
		auth.DELETE("/delete", middlewares.AuthMiddleware(), controllers.DeleteAccount)
	}
}

