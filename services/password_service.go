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

	// Step 1: Verify the token and extract email
	email, err := utils.VerifyResetToken(token)
	if err != nil {
		fmt.Println("❌ Token verification failed:", err)
		return errors.New("invalid or expired reset token")
	}
	fmt.Println("✅ Extracted email from token:", email)

	// Step 2: Fetch user
	user, err := repository.GetUserByEmail(email)
	if err != nil || user == nil || user.ResetToken == nil {
		return errors.New("invalid token")
	}

	// Step 3: Compare stored vs provided token
	dbToken := strings.TrimSpace(*user.ResetToken)
	inputToken := strings.TrimSpace(token)
	if dbToken != inputToken {
		fmt.Println("❌ Reset token mismatch")
		return errors.New("invalid token")
	}

	// ✅ Step 4: Enforce password policy
	if err := utils.ValidatePassword(newPassword); err != nil {
		return err
	}

	// Step 5: Hash the password
	hashed, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.New("failed to hash password")
	}

	// Step 6: Save and cleanup
	if err := repository.UpdatePassword(user.ID, hashed); err != nil {
		return err
	}
	if err := repository.ClearResetToken(user.ID); err != nil {
		return err
	}

	fmt.Println("✅ Password reset successful and token cleared")
	return nil
}

