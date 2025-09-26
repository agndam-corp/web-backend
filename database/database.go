package database

import (
	"fmt"
	"log"
	"os"

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
	// Check if we should reset the database (useful for development or when schema is problematic)
	resetDB := os.Getenv("RESET_DATABASE") == "true"
	if resetDB {
		log.Println("Resetting database - dropping all tables")
		err := DB.Migrator().DropTable(&models.User{}, &models.Session{})
		if err != nil {
			log.Printf("Warning: error dropping tables: %v", err)
			// Continue anyway, might be because tables don't exist yet
		}
	}

	// First, ensure the User table is migrated (this is the referenced table)
	if err := DB.AutoMigrate(&models.User{}); err != nil {
		return fmt.Errorf("error migrating User table: %v", err)
	}

	// Then migrate the Session table
	if err := DB.AutoMigrate(&models.Session{}); err != nil {
		return fmt.Errorf("error migrating Session table: %v", err)
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
