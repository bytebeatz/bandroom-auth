package utils

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims structure for JWT
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateAccessToken creates a short-lived JWT access token (15 min)
func GenerateAccessToken(userID uuid.UUID, email, role string) (string, error) {
	secretKey := []byte(os.Getenv("JWT_SECRET"))

	expirationTime := time.Now().Add(15 * time.Minute)
	//	expirationTime := time.Now().Add(1 * time.Minute)

	claims := &Claims{
		UserID: userID.String(),
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

// GenerateRefreshToken creates a long-lived JWT refresh token (7 days)
func GenerateRefreshToken(userID uuid.UUID) (string, error) {
	secretKey := []byte(os.Getenv("JWT_SECRET"))

	expirationTime := time.Now().Add(7 * 24 * time.Hour)

	claims := &Claims{
		UserID: userID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

// ValidateToken verifies the JWT token and extracts user ID.
func ValidateToken(tokenString string) (*Claims, error) {
	secretKey := []byte(os.Getenv("JWT_SECRET"))

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// 🔍 Debug: Log expiration info
	if claims.ExpiresAt != nil {
		fmt.Printf("[DEBUG] Token expires at: %v | Now: %v\n", claims.ExpiresAt.Time, time.Now())
	}

	// Corrected expiration check
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token has expired")
	}

	return claims, nil
}

// ResetClaims structure for password reset tokens
type ResetClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// GenerateResetToken creates a JWT-based password reset token (valid for 30 min)
func GenerateResetToken(email string) (string, error) {
	secretKey := []byte(os.Getenv("JWT_SECRET"))

	expirationTime := time.Now().Add(30 * time.Minute) // Reset token expires in 30 min
	claims := &ResetClaims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

// VerifyResetToken verifies the password reset token and extracts the email
func VerifyResetToken(tokenString string) (string, error) {
	secretKey := []byte(os.Getenv("JWT_SECRET"))

	// 🐛 DEBUG PRINTS
	fmt.Println("🔑 Raw reset token:", tokenString)
	fmt.Printf("⏰ JWT_SECRET len: %d\n", len(secretKey))

	token, err := jwt.ParseWithClaims(
		tokenString,
		&ResetClaims{},
		func(token *jwt.Token) (any, error) {
			return secretKey, nil
		},
	)
	if err != nil {
		fmt.Println("❌ Token parse error:", err)
		return "", err
	}

	claims, ok := token.Claims.(*ResetClaims)
	if !ok || !token.Valid {
		fmt.Println("❌ Claims invalid or token not valid")
		return "", errors.New("invalid reset token")
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		fmt.Println("⌛ Token expired at:", claims.ExpiresAt.Time)
		return "", errors.New("reset token has expired")
	}

	fmt.Println("✅ Reset token valid for:", claims.Email)
	return claims.Email, nil
}

// GenerateVerificationToken creates a short-lived email verification token (24h)
func GenerateVerificationToken(email string) (string, error) {
	secretKey := []byte(os.Getenv("JWT_SECRET"))

	claims := &jwt.RegisteredClaims{
		Subject:   email,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

// VerifyVerificationToken validates the token and extracts the email
func VerifyVerificationToken(tokenString string) (string, error) {
	fmt.Println("🔍 Raw token:", tokenString)

	secretKey := []byte(os.Getenv("JWT_SECRET"))
	fmt.Println("🔐 JWT_SECRET len:", len(secretKey))

	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (any, error) {
			return secretKey, nil
		},
	)
	if err != nil {
		fmt.Println("❌ Token parse error:", err)
		return "", err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		fmt.Println("❌ Claims invalid or token not valid")
		return "", errors.New("invalid verification token")
	}

	fmt.Println("✅ Token subject (email):", claims.Subject)
	return claims.Subject, nil
}
