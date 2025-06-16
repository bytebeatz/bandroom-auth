package services

import (
	"errors"
	"fmt"

	"github.com/bytebeatz/bandroom-auth/repository"
	"github.com/bytebeatz/bandroom-auth/utils"
)

// SendResetEmail prints the reset token instead of sending an actual email
func SendResetEmail(email, resetToken string) error {
	resetLink := fmt.Sprintf("http://localhost:3000/reset-password?token=%s", resetToken)

	// Print the reset link in the terminal
	fmt.Println("📧 Password Reset Requested:")
	fmt.Printf("User: %s\nReset Link: %s\n", email, resetLink)

	return nil
}

// SendVerification simulates sending a verification email
func SendVerification(email string) error {
	user, err := repository.GetUserByEmail(email)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	token, err := utils.GenerateVerificationToken(user.Email)
	if err != nil {
		return err
	}

	if err := repository.SetVerificationToken(user.ID, token); err != nil {
		return err
	}

	link := fmt.Sprintf("http://localhost:8081/auth/verify?token=%s", token)
	fmt.Printf("📧 Verification email for %s\n🔗 %s\n", user.Email, link)

	return nil
}

// VerifyEmailToken checks and applies verification
func VerifyEmailToken(token string) error {
	email, err := utils.VerifyVerificationToken(token)
	if err != nil {
		return err
	}

	user, err := repository.GetUserByEmail(email)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	if user.IsVerified {
		return errors.New("email already verified")
	}

	if user.VerificationToken == nil {
		fmt.Println("❌ VerificationToken in DB is nil")
		return errors.New("invalid or expired token")
	}

	// Debug print: show both tokens side by side
	fmt.Println("🔍 DB token:      ", *user.VerificationToken)
	fmt.Println("🔍 Incoming token:", token)

	if *user.VerificationToken != token {
		return errors.New("invalid or expired token")
	}

	return repository.MarkEmailVerified(user.ID)
}

