package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/webapp-backend/auth"
	"github.com/yourusername/webapp-backend/aws"
	"github.com/yourusername/webapp-backend/database"
	"github.com/yourusername/webapp-backend/routes"
)

func main() {
	// Initialize JWT key
	auth.InitJWTKey()

	// Initialize database connection with GORM
	database.InitDB()

	// Initialize AWS clients
	aws.InitAWS()

	// Set Gin to debug mode to see more logs during development
	gin.SetMode(gin.DebugMode)

	// Create router
	router := gin.Default()

	// Add logging middleware for debugging
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Add CORS middleware for all routes
	router.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "https://djasko.com" || origin == "https://api.djasko.com" || origin == "http://localhost:3000" || containsAny(origin, []string{"localhost"}) {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")
		
		log.Printf("CORS headers set for origin: %s, method: %s", origin, c.Request.Method)
		
		if c.Request.Method == "OPTIONS" {
			log.Printf("Handling preflight request for: %s", c.Request.URL.Path)
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})

	// Setup routes
	routes.SetupRoutes(router)

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("Starting server on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// containsAny checks if string contains any of the substrings
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if contains(s, sub) {
			return true
		}
	}
	return false
}

// contains checks if string contains substring
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}