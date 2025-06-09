package repository

import (
	"github.com/bytebeatz/bandroom-auth/db"
	"github.com/bytebeatz/bandroom-auth/models"
)

// CreateUser inserts a new user into the database, including username.
func CreateUser(user *models.User) error {
	query := `INSERT INTO users 
		(id, email, username, password_hash, role, refresh_token, created_at, updated_at, last_password_change) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := db.DB.Exec(
		query,
		user.ID,
		user.Email,
		user.Username,
		user.PasswordHash,
		user.Role,
		user.RefreshToken,
		user.CreatedAt,
		user.UpdatedAt,
		user.LastPasswordChange,
	)
	return err
}

