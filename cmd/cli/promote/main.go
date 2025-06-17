package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/bytebeatz/bandroom-auth/config"
	"github.com/bytebeatz/bandroom-auth/db"
	"github.com/bytebeatz/bandroom-auth/repository"
)

func main() {
	// Define --confirm flag
	confirm := flag.Bool("confirm", false, "Confirm the promotion action")
	flag.Parse()

	// Expect exactly one positional argument (email)
	args := flag.Args()
	if len(args) != 1 {
		log.Fatal("❌ Usage: go run cmd/cli/promote.go <email> --confirm")
	}
	email := strings.ToLower(args[0])

	// Require confirmation
	if !*confirm {
		log.Fatalf("⚠️  Confirmation required. Please rerun with --confirm to proceed.")
	}

	// Boot config + DB
	config.LoadConfig()
	db.ConnectDatabase()
	defer db.CloseDatabase()

	// Attempt promotion
	err := repository.PromoteToAdmin(email)
	if err != nil {
		log.Fatalf("❌ Failed to promote user: %v", err)
	}

	fmt.Printf("✅ User %s successfully promoted to admin\n", email)
}
