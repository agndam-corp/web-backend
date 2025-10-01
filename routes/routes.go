package routes

import (
	"net/http"

	"github.com/agndam-corp/web-backend/auth"
	"github.com/agndam-corp/web-backend/aws"
	"github.com/agndam-corp/web-backend/database"
	"github.com/agndam-corp/web-backend/middleware"
	"github.com/agndam-corp/web-backend/models"
	"github.com/gin-gonic/gin"
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

		// Admin endpoint to manage AWS instances
		// adminGroup.POST("/instances", aws.AdminCreateInstance)
		// adminGroup.PUT("/instances/:id", aws.AdminUpdateInstance)
		// adminGroup.DELETE("/instances/:id", aws.AdminDeleteInstance)
	}

	// Protected AWS routes (require authentication)
	protected := router.Group("/")
	protected.Use(middleware.AuthMiddleware)
	{
		// protected.POST("/start", aws.StartInstance)
		// protected.POST("/stop", aws.StopInstance)
		// protected.GET("/status", aws.GetInstanceStatus)

		// Test IAM Anywhere endpoint - uses exact same code as working test
		protected.GET("/test-iam-anywhere", aws.TestIAMAnywhereEndpoint)

		// AWS Instance management routes
		// protected.GET("/instances", aws.GetInstances)
		// protected.POST("/instances", aws.CreateInstance)
		// protected.GET("/instances/:id", aws.GetInstance)
		// protected.PUT("/instances/:id", aws.UpdateInstance)
		// protected.DELETE("/instances/:id", aws.DeleteInstance)

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
