package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the authentication system
type User struct {
	ID                 uuid.UUID  `json:"id"`                      // Unique User ID (UUID)
	Email              string     `json:"email"`                   // User Email (Unique)
	Username           string     `json:"username"`                // Unique public username
	PasswordHash       string     `json:"password_hash"`           // Hashed Password
	Role               string     `json:"role"`                    // User role ('user' or 'admin')
	RefreshToken       *string    `json:"refresh_token,omitempty"` // Stores latest refresh token (nullable)
	IsVerified         bool       `json:"is_verified"`             // Whether email is verified
	VerificationToken  *string    `json:"verification_token"`      // Pending verification token
	VerificationSentAt time.Time  `json:"verification_sent_at"`    // When token was sent
	LastPasswordChange time.Time  `json:"last_password_change"`    // Track last password update
	LastLogin          *time.Time `json:"last_login,omitempty"`    // Optional: track last login
	IsActive           bool       `json:"is_active"`               // Whether account is active
	CreatedAt          time.Time  `json:"created_at"`              // Timestamp when the user was created
	UpdatedAt          time.Time  `json:"updated_at"`              // Timestamp when the user was last updated
	DeletedAt          *time.Time `json:"deleted_at,omitempty"`    // Nullable soft delete timestamp
}

// NewUser creates a new user instance with default fields and timestamps
func NewUser(email, username, hashedPassword, role string) *User {
	currentTime := time.Now()
	return &User{
		ID:                 uuid.New(),
		Email:              email,
		Username:           username,
		PasswordHash:       hashedPassword,
		Role:               role,
		IsVerified:         false,
		IsActive:           true,
		LastPasswordChange: currentTime,
		CreatedAt:          currentTime,
		UpdatedAt:          currentTime,
	}
}

// UpdateUser updates user details and refreshes the updatedAt timestamp
func (u *User) UpdateUser(email, username, hashedPassword, role string) {
	u.Email = email
	u.Username = username
	u.PasswordHash = hashedPassword
	u.Role = role
	u.UpdatedAt = time.Now()
}

// UpdateRefreshToken updates the refresh token for the user
func (u *User) UpdateRefreshToken(refreshToken *string) {
	u.RefreshToken = refreshToken
	u.UpdatedAt = time.Now()
}

