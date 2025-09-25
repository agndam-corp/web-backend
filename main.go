package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/yourusername/webapp-backend/database"
	"github.com/yourusername/webapp-backend/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var ec2Client *ec2.Client
var instanceID string

// SessionTimeout defines how long a user can be inactive before being logged out
const SessionTimeout = 30 * time.Minute // 30 minutes of inactivity

// AccessTokenExpiry defines how long the JWT access token is valid
const AccessTokenExpiry = 15 * time.Minute // 15 minutes

// RefreshTokenExpiry defines how long the refresh token is valid (absolute max)
const RefreshTokenExpiry = 30 * 24 * time.Hour // 30 days

// JWT secret key - should be set via environment variable
var jwtKey = []byte(os.Getenv("JWT_SECRET"))

// TokenClaims represents JWT access token claims
type TokenClaims struct {
	Username     string `json:"username"`
	Role         string `json:"role"`
	SessionID    uint   `json:"session_id"`
	RefreshToken string `json:"refresh_token"`
	jwt.RegisteredClaims
}

func main() {
	// Check if JWT_SECRET is set
	if os.Getenv("JWT_SECRET") == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	// Initialize database connection with GORM
	database.InitDB()

	// Set Gin to debug mode to see more logs during development
	gin.SetMode(gin.DebugMode)

	// Create router
	router := gin.Default()

	// Add logging middleware for debugging
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Add CORS middleware for all routes
	router.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin == "https://djasko.com" || origin == "http://localhost:3000" || strings.Contains(origin, "localhost") {
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

	// Get the instance ID from environment variable
	instanceID = os.Getenv("VPN_INSTANCE_ID")
	if instanceID == "" {
		log.Fatal("VPN_INSTANCE_ID environment variable is required")
	}

	// Load client certificate and key for IAM Roles Anywhere
	certFile := "/etc/ssl/certs/webapp/tls.crt"
	keyFile := "/etc/ssl/certs/webapp/tls.key"
	
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load client certificate: %v", err)
	}
	
	// Load CA certificate
	caCertFile := "/etc/ssl/certs/webapp/ca.crt"
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}
	
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create custom HTTP client with client certificate for IAM Roles Anywhere
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,
			},
		},
	}

	// Load AWS configuration with IAM Roles Anywhere support
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(os.Getenv("AWS_REGION")),
		config.WithHTTPClient(httpClient),
	)
	if err != nil {
		log.Printf("Warning: unable to load AWS SDK config, %v", err)
		// We'll try to create the client anyway, but operations will fail
	}

	// Create STS client
	stsClient := sts.NewFromConfig(cfg)

	// Create credentials using IAM Roles Anywhere
	// The role ARN is determined by the trust policy in the IAM Roles Anywhere profile
	creds := stscreds.NewAssumeRoleProvider(stsClient, "unused-parameter")

	// Create EC2 client with the assumed role credentials
	ec2Client = ec2.NewFromConfig(cfg, func(o *ec2.Options) {
		o.Credentials = aws.NewCredentialsCache(creds)
		o.HTTPClient = httpClient
	})

	// Public routes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Login endpoint to generate JWT token
	router.POST("/login", func(c *gin.Context) {
		log.Printf("Login request received from: %s", c.ClientIP())
		
		var credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&credentials); err != nil {
			log.Printf("Login request failed validation: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		log.Printf("Attempting authentication for user: %s", credentials.Username)
		
		user, authenticated := authenticateUser(credentials.Username, credentials.Password)
		if !authenticated {
			log.Printf("Authentication failed for user: %s", credentials.Username)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		log.Printf("Authentication successful for user: %s", credentials.Username)
		
		// Generate access token and refresh token
		accessToken, refreshToken, err := generateTokens(user)
		if err != nil {
			log.Printf("Failed to generate tokens for user %s: %v", user.Username, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token": accessToken,
			"refresh_token": refreshToken,
			"expires_in":   int64(AccessTokenExpiry.Seconds()),
			"role":         "user", // Default role for now
			"username":     user.Username,
		})
		
		log.Printf("Login successful for user: %s, tokens generated", user.Username)
	})

	// Refresh token endpoint
	router.POST("/refresh", func(c *gin.Context) {
		var refreshTokenReq struct {
			RefreshToken string `json:"refresh_token"`
		}

		if err := c.ShouldBindJSON(&refreshTokenReq); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		// Verify the refresh token exists in database and hasn't expired
		var session models.Session
		result := database.DB.Where("refresh_token = ?", refreshTokenReq.RefreshToken).First(&session)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
				return
			}
			log.Printf("Error querying session: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}

		// Check if absolute lifetime exceeded (30 days)
		if time.Since(session.CreatedAt) > RefreshTokenExpiry {
			// Delete the expired session
			database.DB.Delete(&session)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired (30 days max)"})
			return
		}

		// Check if session timeout exceeded (30 min of inactivity)
		if time.Since(session.LastActivity) > SessionTimeout {
			// Delete the expired session
			database.DB.Delete(&session)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired due to inactivity"})
			return
		}

		// Get user info for the new access token
		var user models.User
		userResult := database.DB.First(&user, session.UserID)
		if userResult.Error != nil {
			log.Printf("Error retrieving user info: %v", userResult.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving user info"})
			return
		}

		// Update last activity
		session.LastActivity = time.Now()
		database.DB.Save(&session)

		// Generate new access token (reusing the same refresh token)
		newAccessToken, err := generateAccessToken(user.Username, "user", uint(session.ID), session.RefreshToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate new access token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token": newAccessToken,
			"expires_in":   int64(AccessTokenExpiry.Seconds()),
			"role":         "user",
			"username":     user.Username,
		})
	})

	// Register endpoint for new users
	router.POST("/register", func(c *gin.Context) {
		var userData struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&userData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		// Validate input
		if userData.Username == "" || userData.Email == "" || userData.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username, email, and password are required"})
			return
		}

		// Check if user already exists
		if userExists(userData.Username, userData.Email) {
			c.JSON(http.StatusConflict, gin.H{"error": "User with that username or email already exists"})
			return
		}

		// Hash the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
			return
		}

		// Create new user
		user := models.User{
			Username: userData.Username,
			Email:    userData.Email,
			Password: string(hashedPassword),
		}

		result := database.DB.Create(&user)
		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
	})

	// Add JWT auth middleware for protected routes
	authorized := router.Group("/")
	authorized.Use(jwtAuthMiddleware())

	// Auth check endpoint that returns user info
	router.GET("/auth-check", jwtAuthMiddleware(), func(c *gin.Context) {
		username, _ := c.Get("username")
		role, _ := c.Get("role")
		c.JSON(http.StatusOK, gin.H{
			"authenticated": true,
			"username":      username,
			"role":          role,
		})
	})

	// Define protected routes that interact with AWS
	// Only admin can start/stop
	authorized.POST("/start", func(c *gin.Context) {
		role, _ := c.Get("role")
		if role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only admin users can start the instance"})
			return
		}
		startInstance(c)
	})

	authorized.POST("/stop", func(c *gin.Context) {
		role, _ := c.Get("role")
		if role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only admin users can stop the instance"})
			return
		}
		stopInstance(c)
	})

	// Both admin and operator can check status
	authorized.GET("/status", getInstanceStatus)

	// Logout endpoint to clear session
	authorized.POST("/logout", func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			return
		}

		// Parse the token to get the refresh token from claims
		claims := &TokenClaims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			// Even if token parsing fails, try to delete any matching session
			c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
			return
		}

		// Remove session from database using the refresh token
		var session models.Session
		result := database.DB.Where("refresh_token = ?", claims.RefreshToken).First(&session)
		if result.Error == nil {
			database.DB.Delete(&session)
		}

		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	})

	// Start server
	router.Run(":8080")
}

func startInstance(c *gin.Context) {
	if ec2Client == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AWS client not initialized"})
		return
	}

	input := &ec2.StartInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.StartInstances(context.TODO(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Instance start initiated",
		"result":  result,
	})
}

func stopInstance(c *gin.Context) {
	if ec2Client == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AWS client not initialized"})
		return
	}

	input := &ec2.StopInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.StopInstances(context.TODO(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Instance stop initiated",
		"result":  result,
	})
}

// authenticateUser authenticates a user against the database
func authenticateUser(username, password string) (*models.User, bool) {
	var user models.User

	// Find user by username or email
	result := database.DB.Where("username = ? OR email = ?", username, username).First(&user)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, false
		}
		log.Printf("Error querying user: %v", result.Error)
		return nil, false
	}

	// Compare the provided password with the hashed password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, false
	}

	return &user, true
}

// userExists checks if a user with the given username or email already exists
func userExists(username, email string) bool {
	var user models.User
	result := database.DB.Where("username = ? OR email = ? ", username, email).First(&user)
	
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return false
		}
		log.Printf("Error checking if user exists: %v", result.Error)
		return false
	}
	
	return true
}

// generateTokens generates both access and refresh tokens
func generateTokens(user *models.User) (string, string, error) {
	// Generate a unique refresh token
	refreshToken := fmt.Sprintf("%d_%s", time.Now().UnixNano(), user.Username)

	// Create session record in database
	session := models.Session{
		UserID:       user.ID,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(RefreshTokenExpiry),
		LastActivity: time.Now(),
		CreatedAt:    time.Now(),
	}

	result := database.DB.Create(&session)
	if result.Error != nil {
		return "", "", fmt.Errorf("error creating session: %v", result.Error)
	}

	// Generate access token
	accessToken, err := generateAccessToken(user.Username, "user", session.ID, refreshToken)
	if err != nil {
		// If access token generation fails, remove the session
		database.DB.Delete(&session)
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// generateAccessToken generates a JWT access token
func generateAccessToken(username, role string, sessionID uint, refreshToken string) (string, error) {
	// Set token expiration time (15 minutes)
	expirationTime := time.Now().Add(AccessTokenExpiry)
	claims := &TokenClaims{
		Username:     username,
		Role:         role,
		SessionID:    sessionID,
		RefreshToken: refreshToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// jwtAuthMiddleware is the middleware for JWT authentication
func jwtAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Bearer {token}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			c.Abort()
			return
		}

		claims := &TokenClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Check if session exists and is not expired
		var session models.Session
		result := database.DB.Where("refresh_token = ?", claims.RefreshToken).First(&session)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Session not found"})
			} else {
				log.Printf("Error querying session: %v", result.Error)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			}
			c.Abort()
			return
		}

		// Check if session has expired due to inactivity
		if time.Now().After(session.ExpiresAt) || time.Since(session.LastActivity) > SessionTimeout {
			// Session expired, delete it
			database.DB.Delete(&session)
			
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired due to inactivity"})
			c.Abort()
			return
		}

		// Update session to extend expiration (sliding session)
		session.LastActivity = time.Now()
		database.DB.Save(&session)

		// Add user info to context
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)

		c.Next()
	}
}

func getInstanceStatus(c *gin.Context) {
	if ec2Client == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AWS client not initialized"})
		return
	}

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.DescribeInstances(context.TODO(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
		return
	}

	instance := result.Reservations[0].Instances[0]
	c.JSON(http.StatusOK, gin.H{
		"instanceId":   *instance.InstanceId,
		"state":        string(instance.State.Name),
		"instanceType": string(instance.InstanceType),
	})
}