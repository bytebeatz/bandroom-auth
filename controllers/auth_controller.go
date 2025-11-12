package controllers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bytebeatz/bandroom-auth/middlewares"
	"github.com/bytebeatz/bandroom-auth/models"
	"github.com/bytebeatz/bandroom-auth/repository"
	"github.com/bytebeatz/bandroom-auth/services"
	"github.com/bytebeatz/bandroom-auth/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AuthValidate verifies the JWT token
func AuthValidate(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := utils.ValidateToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	userUUID, err := uuid.Parse(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
		return
	}

	user, err := repository.GetUserByID(userUUID)
	if err != nil || user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Token is valid",
		"user_id":     user.ID,
		"email":       user.Email,
		"role":        user.Role,
		"is_verified": user.IsVerified,
	})
}

// Register creates a new user account (no user enumeration)
func Register(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	input.Email = strings.ToLower(input.Email)
	input.Username = strings.ToLower(input.Username)

	if err := utils.ValidatePassword(input.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := utils.ValidateUsername(input.Username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := &models.User{
		ID:                 uuid.New(),
		Email:              input.Email,
		Username:           input.Username,
		PasswordHash:       hashedPassword,
		Role:               "user",
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		LastPasswordChange: time.Now(),
	}

	if err := repository.CreateUser(user); err != nil {
		fmt.Printf("⚠️ Registration failed for email=%s: %v\n", input.Email, err)
		c.JSON(http.StatusOK, gin.H{
			"message": "If the email isn't already in use, your account has been created.",
		})
		return
	}

	if err := services.SendVerification(user.Email); err != nil {
		fmt.Println("⚠️ Failed to send verification email:", err)
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "If the email isn't already in use, your account has been created.",
	})
}

// Login authenticates user and issues tokens
func Login(c *gin.Context) {
	var input struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	input.Email = strings.ToLower(input.Email)
	ip := c.ClientIP()

	user, err := repository.VerifyCredentials(input.Email, input.Password)
	if err != nil || user == nil {
		middlewares.TrackFailedLogin(ip)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if !user.IsVerified {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Email not verified. Please check your inbox.",
		})
		return
	}

	if err := repository.UpdateLastLogin(user.ID); err != nil {
		fmt.Println("⚠️ Failed to update last_login:", err)
	}

	accessToken, err := utils.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	refreshToken, err := utils.GenerateRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	if err := repository.UpdateRefreshToken(user.ID, refreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	middlewares.ResetFailedLogin(ip)

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		MaxAge:   60 * 60 * 24 * 7,
	})

	c.JSON(http.StatusOK, gin.H{
		"message":      "Login successful",
		"access_token": accessToken,
	})
}

// RefreshToken issues new access token
func RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token missing or invalid"})
		return
	}

	claims, err := utils.ValidateToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
		return
	}

	user, err := repository.GetUserByID(userID)
	if err != nil || user == nil || user.RefreshToken == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
		return
	}

	storedToken, err := utils.DecryptRefreshToken(*user.RefreshToken)
	if err != nil || storedToken != refreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token does not match"})
		return
	}

	newAccessToken, err := utils.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate access token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": newAccessToken})
}

// Logout clears refresh token
func Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token missing"})
		return
	}

	claims, err := utils.ValidateToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
		return
	}

	storedToken, err := repository.GetRefreshToken(userID)
	if err != nil || storedToken != refreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired session"})
		return
	}

	if err := repository.UpdateRefreshToken(userID, ""); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		MaxAge:   -1,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// GetUser returns authenticated user profile
func GetUser(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userUUID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
		return
	}

	user, err := repository.GetUserByID(userUUID)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"email":    user.Email,
		"username": user.Username,
	})
}

// SendVerificationEmail triggers verification email
func SendVerificationEmail(c *gin.Context) {
	var input struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := services.SendVerification(strings.ToLower(input.Email)); err != nil {
		c.JSON(
			http.StatusOK,
			gin.H{"message": "If not verified, a verification link has been sent."},
		)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "If not verified, a verification link has been sent."})
}

// VerifyEmailToken confirms email verification
func VerifyEmailToken(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing token"})
		return
	}

	if err := services.VerifyEmailToken(token); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email successfully verified"})
}

// ResendVerificationEmail handles re-send flow (no enumeration)
func ResendVerificationEmail(c *gin.Context) {
	var input struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := strings.ToLower(input.Email)
	user, err := repository.GetUserByEmail(email)
	if err != nil || user == nil || user.IsVerified {
		fmt.Printf("🔍 Skipped resend: %s (user not found or already verified)\n", email)
		c.JSON(http.StatusOK, gin.H{"message": "If not verified, a link has been resent."})
		return
	}

	if err := services.SendVerification(email); err != nil {
		fmt.Println("⚠️ Failed to send verification email:", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "If not verified, a link has been resent."})
}

// DeleteAccount performs soft delete
func DeleteAccount(c *gin.Context) {
	userIDRaw, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userID, err := uuid.Parse(userIDRaw.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	if err := repository.SoftDeleteUser(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account scheduled for deletion in 30 days."})
}
