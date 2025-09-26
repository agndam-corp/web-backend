package database

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/yourusername/webapp-backend/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func InitDB() {
	// Get database connection details from environment variables
	dbHost := getEnv("DB_HOST", "webapp-mariadb.webapp.svc.cluster.local")
	dbPort := getEnv("DB_PORT", "3306")
	dbUser := getEnv("DB_USER", "webapp-user")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := getEnv("DB_NAME", "webapp-db")

	if dbPassword == "" {
		log.Fatal("DB_PASSWORD environment variable is required")
	}

	// Format connection string for MySQL/MariaDB
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", dbUser, dbPassword, dbHost, dbPort, dbName)

	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info), // Change to logger.Silent for production
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Run migrations
	err = Migrate()
	if err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	log.Println("Successfully connected to the database and ran migrations")
}

func Migrate() error {
	// First, handle any foreign key constraints that might prevent column modifications
	// Specifically handle the sessions.user_id foreign key constraint issue
	if err := handleForeignKeyConstraints(); err != nil {
		return fmt.Errorf("error handling foreign key constraints: %v", err)
	}

	// Auto-migrate the schema
	err := DB.AutoMigrate(&models.User{}, &models.Session{})
	if err != nil {
		return fmt.Errorf("error migrating database: %v", err)
	}

	log.Println("Database migration completed successfully")
	return nil
}

// handleForeignKeyConstraints handles foreign key constraints that might prevent column modifications
func handleForeignKeyConstraints() error {
	// Check if foreign key exists and drop it temporarily if needed
	// This is needed because MySQL/MariaDB prevents modifying columns that are part of foreign key constraints
	var result *gorm.DB
	
	// Attempt to drop the foreign key constraint if it exists
	// The constraint name follows MySQL/MariaDB naming convention
	result = DB.Exec("ALTER TABLE `sessions` DROP FOREIGN KEY `sessions_ibfk_1`")
	
	// Check if the error indicates the foreign key doesn't exist (which is fine)
	if result.Error != nil && !isForeignKeyDoesNotExistError(result.Error) {
		return result.Error
	}
	
	return nil
}

// isForeignKeyDoesNotExistError checks if the error is related to foreign key not existing
func isForeignKeyDoesNotExistError(err error) bool {
	errStr := err.Error()
	// Check for error indicating foreign key doesn't exist
	// Different MySQL/MariaDB versions may have different messages
	return containsAny(errStr, []string{
		"Check that column/key exists",
		"key does not exist",
		"foreign key constraint does not exist",
		"errno 1091", // MySQL error code for "Can't DROP"
	})
}

// containsAny checks if string contains any of the substrings
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}