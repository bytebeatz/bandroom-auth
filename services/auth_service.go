package services

import (
	"errors"
	"strings"
	"time"

	"github.com/bytebeatz/bandroom-auth/models"
	"github.com/bytebeatz/bandroom-auth/repository"
	"github.com/bytebeatz/bandroom-auth/utils"

	"github.com/google/uuid"
)

// RegisterUser registers a new user with email, username, and password.
func RegisterUser(email, username, password string) (*models.User, error) {
	email = strings.ToLower(email)
	username = strings.TrimSpace(username)

	// Check if user already exists
	existingUser, _ := repository.GetUserByEmail(email)
	if existingUser != nil {
		return nil, errors.New("user already exists")
	}

	// Validate inputs
	if err := utils.ValidateUsername(username); err != nil {
		return nil, err
	}

	if err := utils.ValidatePassword(password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Create user model
	user := &models.User{
		ID:                 uuid.New(),
		Email:              email,
		Username:           username,
		PasswordHash:       hashedPassword,
		Role:               "user",
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		LastPasswordChange: time.Now(),
	}

	// Insert into DB
	if err = repository.CreateUser(user); err != nil {
		return nil, err
	}

	return user, nil
}

// LoginUser authenticates a user and returns access and refresh tokens.
func LoginUser(email, password string) (string, string, error) {
	email = strings.ToLower(email)

	user, err := repository.GetUserByEmail(email)
	if err != nil || user == nil {
		return "", "", errors.New("invalid credentials")
	}

	if !utils.ComparePassword(user.PasswordHash, password) {
		return "", "", errors.New("invalid credentials")
	}

	accessToken, err := utils.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := repository.GetRefreshToken(user.ID)
	if err != nil {
		return "", "", err
	}

	if refreshToken == "" {
		refreshToken, err = utils.GenerateRefreshToken(user.ID)
		if err != nil {
			return "", "", err
		}

		if err = repository.UpdateRefreshToken(user.ID, refreshToken); err != nil {
			return "", "", err
		}
	}

	return accessToken, refreshToken, nil
}

// LogoutUser removes the refresh token from the database.
func LogoutUser(userID uuid.UUID) error {
	return repository.UpdateRefreshToken(userID, "")
}

// RefreshToken generates a new access token using the refresh token.
func RefreshToken(userID uuid.UUID, providedRefreshToken string) (string, error) {
	storedRefreshToken, err := repository.GetRefreshToken(userID)
	if err != nil {
		return "", errors.New("failed to retrieve stored refresh token")
	}

	if storedRefreshToken == "" || storedRefreshToken != providedRefreshToken {
		return "", errors.New("invalid or expired refresh token")
	}

	user, err := repository.GetUserByID(userID)
	if err != nil || user == nil {
		return "", errors.New("user not found")
	}

	newAccessToken, err := utils.GenerateAccessToken(userID, user.Email, user.Role)
	if err != nil {
		return "", errors.New("failed to generate new access token")
	}

	return newAccessToken, nil
}

// ChangePassword updates the user's password securely.
func ChangePassword(userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := repository.GetUserByID(userID)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	if !utils.ComparePassword(user.PasswordHash, oldPassword) {
		return errors.New("incorrect current password")
	}

	if err = utils.ValidatePassword(newPassword); err != nil {
		return err
	}

	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return err
	}

	if err = repository.UpdatePassword(userID, hashedPassword); err != nil {
		return errors.New("failed to update password")
	}

	return nil
}

// GetUser fetches user details by ID.
func GetUser(userID uuid.UUID) (*models.User, error) {
	user, err := repository.GetUserByID(userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}
	return user, nil
}
