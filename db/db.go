package db

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/bytebeatz/bandroom-auth/config"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func ConnectDatabase() {
	var err error

	DB, err = sql.Open("postgres", config.Config.DatabaseURL)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatalf("Cannot connect to database: %v", err)
	}

	fmt.Println("Connected to the database successfully!")
}

func CloseDatabase() {
	if DB != nil {
		if err := DB.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}
}
