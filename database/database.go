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
	// The issue occurs when GORM tries to change column type with foreign key constraint
	// To safely handle this, we need to drop foreign key constraints, 
	// perform the migration, and let GORM recreate the constraints properly
	
	// Get GORM's migrator instance
	migrator := DB.Migrator()
	
	// Check if sessions table exists
	sessionsTableExists := migrator.HasTable(&models.Session{})
	
	if sessionsTableExists {
		// If sessions table exists, we may need to handle existing foreign keys
		// Try to drop the foreign key constraint temporarily
		// Check if foreign key exists first
		var fkExists int64
		DB.Raw(`
			SELECT COUNT(*) 
			FROM information_schema.KEY_COLUMN_USAGE 
			WHERE TABLE_SCHEMA = DATABASE() 
			AND TABLE_NAME = 'sessions' 
			AND REFERENCED_TABLE_NAME = 'users'
			AND CONSTRAINT_NAME = 'sessions_ibfk_1'`).Scan(&fkExists)

		if fkExists > 0 {
			// Drop the foreign key constraint before migration
			if err := DB.Exec("ALTER TABLE `sessions` DROP FOREIGN KEY `sessions_ibfk_1`").Error; err != nil {
				// If constraint doesn't exist now (race condition), continue
				if !strings.Contains(err.Error(), "check that it exists") {
					log.Printf("Warning: could not drop foreign key: %v", err)
				}
			}
		}
	}

	// Now run the auto-migration which will handle column types and recreate constraints
	if err := DB.AutoMigrate(&models.User{}, &models.Session{}); err != nil {
		return fmt.Errorf("error migrating database: %v", err)
	}

	log.Println("Database migration completed successfully")
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}