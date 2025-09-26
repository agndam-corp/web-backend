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
	// The issue occurs when GORM tries to change column type with foreign key constraint
	// To safely handle this, we'll check the current schema and handle migrations carefully
	
	migrator := DB.Migrator()
	
	// Check if the sessions table exists
	sessionsTableExists := migrator.HasTable(&models.Session{})
	
	if sessionsTableExists {
		// If the sessions table already exists, we need to handle potential column type mismatches
		// First, check if the user_id column has the expected type
		
		// Get column information for user_id
		var columnInfo []map[string]interface{}
		DB.Raw(`
			SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, EXTRA
			FROM information_schema.COLUMNS 
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sessions' AND COLUMN_NAME = 'user_id'
		`).Scan(&columnInfo)
		
		if len(columnInfo) > 0 {
			// The column exists, check its type
			log.Printf("Current user_id column info: %+v", columnInfo[0])
			
			// Since the error indicates GORM wants to change to 'bigint unsigned NOT NULL'
			// We'll try a different approach: temporarily disable foreign key checks
			if err := DB.Exec("SET FOREIGN_KEY_CHECKS = 0").Error; err != nil {
				return fmt.Errorf("error disabling foreign key checks: %v", err)
			}
			
			// Perform the migration with foreign key checks disabled
			if err := DB.AutoMigrate(&models.User{}, &models.Session{}); err != nil {
				// Re-enable foreign key checks before returning error
				DB.Exec("SET FOREIGN_KEY_CHECKS = 1")
				return fmt.Errorf("error migrating database: %v", err)
			}
			
			// Re-enable foreign key checks
			if err := DB.Exec("SET FOREIGN_KEY_CHECKS = 1").Error; err != nil {
				log.Printf("Warning: error re-enabling foreign key checks: %v", err)
			}
		} else {
			// Column doesn't exist, safe to migrate normally
			if err := DB.AutoMigrate(&models.User{}, &models.Session{}); err != nil {
				return fmt.Errorf("error migrating database: %v", err)
			}
		}
	} else {
		// If table doesn't exist, normal migration is safe
		if err := DB.AutoMigrate(&models.User{}, &models.Session{}); err != nil {
			return fmt.Errorf("error migrating database: %v", err)
		}
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