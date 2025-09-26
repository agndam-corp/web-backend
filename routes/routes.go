package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/webapp-backend/auth"
	"github.com/yourusername/webapp-backend/aws"
	"github.com/yourusername/webapp-backend/database"
	"github.com/yourusername/webapp-backend/middleware"
	"github.com/yourusername/webapp-backend/models"
	"golang.org/x/crypto/bcrypt"
)

// SetupRoutes configures all the application routes
func SetupRoutes(router *gin.Engine) {
	// Public routes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Authentication routes
	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login", auth.Login)
		authGroup.POST("/register", auth.Register)
		authGroup.POST("/refresh", auth.RefreshToken)
	}

	// Admin-only routes
	adminGroup := router.Group("/admin")
	adminGroup.Use(middleware.AdminMiddleware) // Require admin access
	{
		adminGroup.POST("/create-admin", func(c *gin.Context) {
			var adminData struct {
				Username string `json:"username" binding:"required"`
				Email    string `json:"email" binding:"required"`
				Password string `json:"password" binding:"required,min=6"`
			}

			if err := c.ShouldBindJSON(&adminData); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			// Check if user already exists
			var existingUser models.User
			if err := database.DB.Where("username = ? OR email = ?", adminData.Username, adminData.Email).First(&existingUser).Error; err == nil {
				c.JSON(http.StatusConflict, gin.H{"error": "User with this username or email already exists"})
				return
			}

			// Hash the password
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminData.Password), bcrypt.DefaultCost)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
				return
			}

			// Create new admin user
			newAdmin := models.User{
				Username: adminData.Username,
				Email:    adminData.Email,
				Password: string(hashedPassword),
				Role:     models.RoleAdmin, // Explicitly set to admin role
			}

			if err := database.DB.Create(&newAdmin).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create admin user"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message":  "Admin user created successfully",
				"username": newAdmin.Username,
				"role":     string(newAdmin.Role),
			})
		})
	}

	// Protected AWS routes (require authentication)
	protected := router.Group("/")
	protected.Use(middleware.AuthMiddleware)
	{
		protected.POST("/start", aws.StartInstance)
		protected.POST("/stop", aws.StopInstance)
		protected.GET("/status", aws.GetInstanceStatus)

		// Auth check endpoint that returns user info
		protected.GET("/auth-check", func(c *gin.Context) {
			username, _ := c.Get("username")
			role, _ := c.Get("role")
			c.JSON(http.StatusOK, gin.H{
				"authenticated": true,
				"username":      username,
				"role":          role,
			})
		})
	}
}
