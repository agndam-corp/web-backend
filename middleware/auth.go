package middleware

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/yourusername/webapp-backend/auth"
	"github.com/yourusername/webapp-backend/database"
	"github.com/yourusername/webapp-backend/models"
)

// AuthMiddleware checks if user is authenticated
func AuthMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	log.Printf("Auth middleware: Authorization header: %s", authHeader)
	
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		log.Printf("Auth middleware: Missing or invalid authorization header")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing or invalid"})
		c.Abort()
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	log.Printf("Auth middleware: Token string length: %d", len(tokenString))

	claims := &auth.TokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return auth.GetJWTKey(), nil
	})

	if err != nil || !token.Valid {
		log.Printf("Auth middleware: Token validation failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		c.Abort()
		return
	}

	log.Printf("Auth middleware: Token claims - Username: %s, Role: %s, Session ID: %d", claims.Username, claims.Role, claims.SessionID)

	// Check if session is still valid
	var session models.Session
	result := database.DB.Where("id = ?", claims.SessionID).First(&session)
	if result.Error != nil {
		log.Printf("Auth middleware: Session not found: %v", result.Error)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session not found"})
		c.Abort()
		return
	}

	if time.Since(session.LastActivity) > auth.SessionTimeout {
		log.Printf("Auth middleware: Session expired due to inactivity")
		// Delete the expired session
		database.DB.Delete(&session)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired due to inactivity"})
		c.Abort()
		return
	}
	
	// Verify that the session belongs to the expected user (if subject is set)
	if claims.RegisteredClaims.Subject != "" {
		expectedUserID, err := strconv.ParseUint(claims.RegisteredClaims.Subject, 10, 32)
		if err == nil && uint(expectedUserID) != session.UserID {
			log.Printf("Auth middleware: Session mismatch - Expected user ID %d, got %d", uint(expectedUserID), session.UserID)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session does not belong to user"})
			c.Abort()
			return
		}
	}

	// Update last activity
	database.DB.Model(&session).Update("LastActivity", time.Now())
	log.Printf("Auth middleware: Session activity updated for user ID: %s", claims.RegisteredClaims.Subject)

	// Store user info in context for use in handlers
	c.Set("user_id", claims.RegisteredClaims.Subject)
	c.Set("username", claims.Username)
	c.Set("role", claims.Role)
	log.Printf("Auth middleware: User authenticated - Username: %s, Role: %s", claims.Username, claims.Role)
	c.Next()
}

// AdminMiddleware checks if user has admin role
func AdminMiddleware(c *gin.Context) {
	log.Printf("Admin middleware: Checking admin access")
	AuthMiddleware(c)
	if c.IsAborted() {
		log.Printf("Admin middleware: Authentication failed, aborting")
		return
	}

	role, exists := c.Get("role")
	log.Printf("Admin middleware: User role check - Role: %v, Exists: %t", role, exists)
	
	if !exists || role != string(models.RoleAdmin) {
		log.Printf("Admin middleware: Access denied - User role: %v, Required: admin", role)
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		c.Abort()
		return
	}

	log.Printf("Admin middleware: Admin access granted")
	c.Next()
}