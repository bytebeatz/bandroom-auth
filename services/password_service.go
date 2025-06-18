package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bytebeatz/bandroom-auth/repository"
	"github.com/bytebeatz/bandroom-auth/utils"
	"github.com/redis/go-redis/v9"
)

// 🔒 Redis client for rate-limiting
var redisClient = redis.NewClient(&redis.Options{
	Addr: "localhost:6379", // or use config.Config.RedisHost if abstracted
})

// Rate limit constants
const (
	resetLimitKeyPrefix = "reset:"
	resetLimitCount     = 5
	resetLimitWindow    = time.Hour
)

// canRequestPasswordReset checks if reset can proceed based on rate limit
func canRequestPasswordReset(email string) (bool, error) {
	ctx := context.Background()
	key := resetLimitKeyPrefix + strings.ToLower(email)

	// Atomically increment count
	count, err := redisClient.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}

	// Set expiration if this is the first reset attempt
	if count == 1 {
		_ = redisClient.Expire(ctx, key, resetLimitWindow).Err()
	}

	// ✅ Enforce rate limit
	if count > resetLimitCount {
		return false, nil
	}
	return true, nil
}

// SendResetToken generates a reset token and stores it in the DB
func SendResetToken(email string) error {
	email = strings.ToLower(email)

	// ✅ Rate-limit enforcement
	allowed, err := canRequestPasswordReset(email)
	if err != nil {
		return fmt.Errorf("could not validate reset rate limit")
	}
	if !allowed {
		return fmt.Errorf(
			"rate limit exceeded: only %d reset requests allowed per hour",
			resetLimitCount,
		)
	}

	user, err := repository.GetUserByEmail(email)
	if err != nil || user == nil {
		// ❗ Do not expose user existence — return success regardless
		fmt.Println("❌ Debug: No user found for email:", email)
		return nil
	}

	token, err := utils.GenerateResetToken(user.Email)
	if err != nil {
		return err
	}

	if err := repository.SetResetToken(user.ID, token); err != nil {
		return err
	}

	resetLink := fmt.Sprintf("http://localhost:3000/reset-password?token=%s", token)
	fmt.Printf("🔑 Reset link for %s\n🔗 %s\n", email, resetLink)
	return nil
}

// ResetPassword validates token and updates the user's password
func ResetPassword(token, newPassword string) error {
	fmt.Printf("🧪 Received token: [%s] (len=%d)\n", token, len(token))

	email, err := utils.VerifyResetToken(token)
	if err != nil {
		fmt.Println("❌ Token verification failed:", err)
		return errors.New("invalid or expired reset token")
	}
	fmt.Println("✅ Extracted email from token:", email)

	user, err := repository.GetUserByEmail(email)
	if err != nil || user == nil {
		fmt.Println("❌ No user found with email:", email)
		return errors.New("invalid token")
	}
	if user.ResetToken == nil {
		fmt.Println("❌ User has no reset token in DB")
		return errors.New("invalid token")
	}

	dbToken := strings.TrimSpace(*user.ResetToken)
	inputToken := strings.TrimSpace(token)

	fmt.Printf("📦 DB token: [%s] (len=%d)\n", dbToken, len(dbToken))
	fmt.Printf("🎯 Input token: [%s] (len=%d)\n", inputToken, len(inputToken))

	if dbToken != inputToken {
		fmt.Println("❌ Reset token mismatch")
		return errors.New("invalid token")
	}

	hashed, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.New("failed to hash password")
	}

	if err := repository.UpdatePassword(user.ID, hashed); err != nil {
		return err
	}
	if err := repository.ClearResetToken(user.ID); err != nil {
		return err
	}

	fmt.Println("✅ Password reset successful and token cleared")
	return nil
}

