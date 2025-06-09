package utils

import (
	"errors"
	"regexp"
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)

// ValidateUsername checks if the username meets allowed criteria
func ValidateUsername(username string) error {
	if !usernameRegex.MatchString(username) {
		return errors.New(
			"username must be 3–20 characters and only contain letters, numbers, and underscores",
		)
	}
	return nil
}
