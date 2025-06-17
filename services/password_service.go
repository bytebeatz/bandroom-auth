package services

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bytebeatz/bandroom-auth/repository"
	"github.com/bytebeatz/bandroom-auth/utils"
)

// SendResetToken generates a reset token and stores it in the DB
func SendResetToken(email string) error {
	user, err := repository.GetUserByEmail(email)
	if err != nil || user == nil {
		return errors.New("user not found")
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

	// 1. Decode token and get email
	email, err := utils.VerifyResetToken(token)
	if err != nil {
		fmt.Println("❌ Token verification failed:", err)
		return errors.New("invalid or expired reset token")
	}
	fmt.Println("✅ Extracted email from token:", email)

	// 2. Get user
	user, err := repository.GetUserByEmail(email)
	if err != nil || user == nil {
		fmt.Println("❌ No user found with email:", email)
		return errors.New("user not found")
	}
	if user.ResetToken == nil {
		fmt.Println("❌ User has no reset token in DB")
		return errors.New("invalid token (missing stored token)")
	}

	dbToken := strings.TrimSpace(*user.ResetToken)
	inputToken := strings.TrimSpace(token)

	fmt.Printf("📦 DB token: [%s] (len=%d)\n", dbToken, len(dbToken))
	fmt.Printf("🎯 Input token: [%s] (len=%d)\n", inputToken, len(inputToken))

	if dbToken != inputToken {
		fmt.Println("❌ Reset token mismatch")
		return errors.New("invalid token (does not match stored token)")
	}

	// 3. Hash new password
	hashed, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.New("failed to hash password")
	}

	// 4. Update password and clear reset token
	if err := repository.UpdatePassword(user.ID, hashed); err != nil {
		return err
	}
	if err := repository.ClearResetToken(user.ID); err != nil {
		return err
	}

	fmt.Println("✅ Password reset successful and token cleared")
	return nil
}

