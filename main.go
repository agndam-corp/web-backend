package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
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
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var ec2Client *ec2.Client
var instanceID string
var db *sql.DB

// JWT secret key - should be set via environment variable
var jwtKey = []byte(os.Getenv("JWT_SECRET"))

// Claims represents JWT claims
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// User represents a user in the system
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"-"`
}

func initDB() {
	// Get database connection details from environment variables
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "webapp-mariadb.webapp.svc.cluster.local" // Default service name
	}
	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		dbPort = "3306" // Default MariaDB port
	}
	dbUser := os.Getenv("DB_USER")
	if dbUser == "" {
		dbUser = "webapp_user"
	}
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		dbName = "webapp_db"
	}

	if dbPassword == "" {
		log.Fatal("DB_PASSWORD environment variable is required")
	}

	// Format connection string for MySQL/MariaDB
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err = db.PingContext(ctx); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Successfully connected to the database")
}

func main() {
	// Check if JWT_SECRET is set
	if os.Getenv("JWT_SECRET") == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	// Initialize database connection
	initDB()

	// Set Gin to debug mode to see more logs during development
	gin.SetMode(gin.DebugMode) // Changed from ReleaseMode for better debugging

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
		
		token, err := generateToken(user.Username, "user") // Default role for now
		if err != nil {
			log.Printf("Failed to generate token for user %s: %v", user.Username, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":      token,
			"role":       "user", // Default role for now
			"expires_in": 3600, // 1 hour in seconds
			"username":   user.Username,
		})
		
		log.Printf("Login successful for user: %s, token generated", user.Username)
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

		// Insert new user
		query := "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)"
		_, err = db.Exec(query, userData.Username, userData.Email, string(hashedPassword))
		if err != nil {
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
func authenticateUser(username, password string) (*User, bool) {
	var user User
	var hashedPassword string

	query := "SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ?"
	err := db.QueryRow(query, username, username).Scan(&user.ID, &user.Username, &user.Email, &hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, false
		}
		log.Printf("Error querying user: %v", err)
		return nil, false
	}

	// Compare the provided password with the hashed password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return nil, false
	}

	// Don't expose the password hash
	user.Password = ""
	return &user, true
}

// userExists checks if a user with the given username or email already exists
func userExists(username, email string) bool {
	var count int
	query := "SELECT COUNT(*) FROM users WHERE username = ? OR email = ?"
	err := db.QueryRow(query, username, email).Scan(&count)
	if err != nil {
		log.Printf("Error checking if user exists: %v", err)
		return false
	}
	return count > 0
}

// generateToken generates a JWT token for a user
func generateToken(username, role string) (string, error) {
	// Set token expiration time (1 hour)
	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		Username: username,
		Role:     role,
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

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

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