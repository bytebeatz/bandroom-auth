package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/bytebeatz/bandroom-auth/config"
	"github.com/bytebeatz/bandroom-auth/db"
	"github.com/bytebeatz/bandroom-auth/models"
	"github.com/bytebeatz/bandroom-auth/utils"
	"github.com/google/uuid"
)

// GetUserByEmail retrieves a user by email for authentication.
func GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	var (
		refreshToken       sql.NullString
		verificationToken  sql.NullString
		verificationSentAt sql.NullTime
		lastLogin          sql.NullTime
		deletedAt          sql.NullTime
	)

	query := `SELECT 
		id, email, username, password_hash, role, 
		refresh_token, is_verified, verification_token, verification_sent_at, 
		is_active, last_login, last_password_change, 
		created_at, updated_at, deleted_at 
		FROM users WHERE email = $1 AND deleted_at IS NULL`

	row := db.DB.QueryRow(query, email)
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.Role,
		&refreshToken,
		&user.IsVerified,
		&verificationToken,
		&verificationSentAt,
		&user.IsActive,
		&lastLogin,
		&user.LastPasswordChange,
		&user.CreatedAt,
		&user.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fmt.Println("❌ Debug: No user found for email:", email)
			return nil, nil
		}
		return nil, err
	}

	if refreshToken.Valid {
		user.RefreshToken = &refreshToken.String
	}
	if verificationToken.Valid {
		user.VerificationToken = &verificationToken.String
	}
	if verificationSentAt.Valid {
		user.VerificationSentAt = verificationSentAt.Time
	}
	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}
	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return &user, nil
}

// GetUserByID retrieves a user by UUID.
func GetUserByID(userID uuid.UUID) (*models.User, error) {
	var user models.User
	var (
		refreshToken       sql.NullString
		verificationToken  sql.NullString
		verificationSentAt sql.NullTime
		lastLogin          sql.NullTime
		deletedAt          sql.NullTime
	)

	query := `SELECT 
		id, email, username, password_hash, role, 
		refresh_token, is_verified, verification_token, verification_sent_at, 
		is_active, last_login, last_password_change, 
		created_at, updated_at, deleted_at 
		FROM users 
		WHERE id = $1 AND deleted_at IS NULL`

	row := db.DB.QueryRow(query, userID)
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.Role,
		&refreshToken,
		&user.IsVerified,
		&verificationToken,
		&verificationSentAt,
		&user.IsActive,
		&lastLogin,
		&user.LastPasswordChange,
		&user.CreatedAt,
		&user.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if refreshToken.Valid {
		user.RefreshToken = &refreshToken.String
	}
	if verificationToken.Valid {
		user.VerificationToken = &verificationToken.String
	}
	if verificationSentAt.Valid {
		user.VerificationSentAt = verificationSentAt.Time
	}
	if lastLogin.Valid {
		user.LastLogin = &lastLogin.Time
	}
	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return &user, nil
}

// VerifyCredentials checks if the provided email and password are correct.
func VerifyCredentials(email, inputPassword string) (*models.User, error) {
	user, err := GetUserByEmail(email)
	if err != nil || user == nil {
		return nil, errors.New("invalid credentials")
	}

	if !utils.ComparePassword(user.PasswordHash, inputPassword) {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}

// UpdateUser modifies a user's email, password, and role.
func UpdateUser(user *models.User) error {
	query := `UPDATE users SET email = $1, username = $2, password_hash = $3, role = $4, updated_at = current_timestamp WHERE id = $5`
	_, err := db.DB.Exec(query, user.Email, user.Username, user.PasswordHash, user.Role, user.ID)
	return err
}

// UpdatePassword updates a user's password securely.
func UpdatePassword(userID uuid.UUID, hashedPassword string) error {
	query := `UPDATE users SET password_hash = $1, updated_at = current_timestamp, last_password_change = current_timestamp WHERE id = $2`
	_, err := db.DB.Exec(query, hashedPassword, userID)
	return err
}

// UpdateRefreshToken securely stores or removes the refresh token.
func UpdateRefreshToken(userID uuid.UUID, refreshToken string) error {
	var err error
	var query string

	if refreshToken == "" {
		query = `UPDATE users SET refresh_token = NULL, updated_at = current_timestamp WHERE id = $1`
		_, err = db.DB.Exec(query, userID)
	} else {
		encryptedToken, encErr := utils.EncryptRefreshToken(refreshToken)
		if encErr != nil {
			return encErr
		}
		query = `UPDATE users SET refresh_token = $1, updated_at = current_timestamp WHERE id = $2`
		_, err = db.DB.Exec(query, encryptedToken, userID)
	}

	return err
}

// GetRefreshToken retrieves and decrypts the stored refresh token.
func GetRefreshToken(userID uuid.UUID) (string, error) {
	var encryptedToken sql.NullString
	query := `SELECT refresh_token FROM users WHERE id = $1`

	err := db.DB.QueryRow(query, userID).Scan(&encryptedToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}

	if !encryptedToken.Valid {
		return "", nil
	}

	return utils.DecryptRefreshToken(encryptedToken.String)
}

// DeleteUser permanently removes a user from the database.
func DeleteUser(userID uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := db.DB.Exec(query, userID)
	return err
}

// ClearRefreshToken properly removes the refresh token from the database
func ClearRefreshToken(userID uuid.UUID) error {
	query := `UPDATE users SET refresh_token = NULL, updated_at = current_timestamp WHERE id = $1`
	_, err := db.DB.Exec(query, userID)
	return err
}

// SetVerificationToken updates the user's verification token in the DB
func SetVerificationToken(userID uuid.UUID, token string) error {
	query := `UPDATE users SET verification_token = $1, verification_sent_at = NOW(), updated_at = NOW() WHERE id = $2`
	_, err := db.DB.Exec(query, token, userID)
	return err
}

// MarkEmailVerified sets is_verified = true and clears verification_token
func MarkEmailVerified(userID uuid.UUID) error {
	query := `UPDATE users SET is_verified = TRUE, verification_token = NULL, updated_at = NOW() WHERE id = $1`
	_, err := db.DB.Exec(query, userID)
	return err
}

// UpdateLastLogin sets the last_login timestamp
func UpdateLastLogin(userID uuid.UUID) error {
	query := `UPDATE users SET last_login = NOW(), updated_at = NOW() WHERE id = $1`
	_, err := db.DB.Exec(query, userID)
	return err
}

// SoftDeleteUser marks a user as deleted and inactive
func SoftDeleteUser(userID uuid.UUID) error {
	query := `UPDATE users SET deleted_at = NOW(), is_active = FALSE, updated_at = NOW() WHERE id = $1`
	_, err := db.DB.Exec(query, userID)
	return err
}

// PurgeDeletedUsers deletes users whose deleted_at is older than the configured grace period
func PurgeDeletedUsers() error {
	grace := config.Config.DeletionGracePeriod
	query := fmt.Sprintf(`
		DELETE FROM users
		WHERE deleted_at IS NOT NULL
		AND deleted_at < NOW() - INTERVAL '%s'`, grace)

	result, err := db.DB.Exec(query)
	if err != nil {
		return err
	}

	count, _ := result.RowsAffected()
	if count > 0 {
		log.Printf("🧹 Purged %d user(s) deleted more than %s ago", count, grace)
	}
	return nil
}

// PromoteToAdmin sets the role of a user to 'admin'
func PromoteToAdmin(email string) error {
	query := `UPDATE users SET role = 'admin', updated_at = NOW() WHERE email = $1 AND deleted_at IS NULL`
	result, err := db.DB.Exec(query, email)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no matching active user found with email: %s", email)
	}
	return nil
}

// DemoteToUser changes a user's role from admin to user
func DemoteToUser(email string) error {
	query := `UPDATE users SET role = 'user', updated_at = NOW() WHERE email = $1 AND deleted_at IS NULL`
	result, err := db.DB.Exec(query, email)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no user found or already demoted")
	}
	return nil
}

