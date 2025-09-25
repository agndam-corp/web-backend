package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"golang.org/x/crypto/bcrypt"
)

var ec2Client *ec2.Client
var instanceID string

// JWT secret key - should be set via environment variable
var jwtKey = []byte(os.Getenv("JWT_SECRET"))

// User represents a user in the system
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"` // "admin" or "operator"
}

// Users map for authentication (in production you might want to load from a file or database)
var users = map[string]User{
	"admin": {
		Username: "admin",
		Password: hashPassword(os.Getenv("ADMIN_PASSWORD")),
		Role:     "admin",
	},
	"operator": {
		Username: "operator",
		Password: hashPassword(os.Getenv("OPERATOR_PASSWORD")),
		Role:     "operator",
	},
}

// Claims represents JWT claims
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func main() {
	// Check if JWT_SECRET is set
	if os.Getenv("JWT_SECRET") == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	// Set Gin to release mode
	gin.SetMode(gin.ReleaseMode)

	// Create router
	router := gin.Default()

	// Add CORS middleware for all routes
	router.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin == "https://djasko.com" || origin == "http://localhost:3000" {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")
		
		if c.Request.Method == "OPTIONS" {
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
		var credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
			return
		}

		user, authenticated := authenticateUser(credentials.Username, credentials.Password)
		if !authenticated {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		token, err := generateToken(user.Username, user.Role)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":  token,
			"role":   user.Role,
			"expires_in": 3600, // 1 hour in seconds
		})
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

// hashPassword hashes the password using bcrypt
func hashPassword(password string) string {
	if password == "" {
		return ""
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	return string(hashed)
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

// authenticateUser authenticates a user against the credentials
func authenticateUser(username, password string) (*User, bool) {
	user, exists := users[username]
	if !exists {
		return nil, false
	}

	// Compare the provided password with the hashed password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, false
	}

	return &user, true
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