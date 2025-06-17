package main

import (
	"fmt"
	"log"
	"os"

	"github.com/bytebeatz/bandroom-auth/config"
	"github.com/bytebeatz/bandroom-auth/db"
	"github.com/bytebeatz/bandroom-auth/repository"
)

func main() {
	if len(os.Args) < 3 || os.Args[2] != "--confirm" {
		log.Fatal("❌ Usage: go run cmd/cli/demote/main.go <email> --confirm")
	}
	email := os.Args[1]

	// Load config and DB
	config.LoadConfig()
	db.ConnectDatabase()
	defer db.CloseDatabase()

	// Demote user to 'user'
	err := repository.DemoteToUser(email)
	if err != nil {
		log.Fatalf("❌ Failed to demote user: %v", err)
	}

	fmt.Printf("✅ User %s successfully demoted to 'user' role\n", email)
}

