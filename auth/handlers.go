package auth

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/yourusername/webapp-backend/database"
	"github.com/yourusername/webapp-backend/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// @title Webapp API
// @version 1.0
// @description VPN Control Panel API
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host api.djasko.com
// @BasePath /api/v1
// @schemes https

// TokenClaims represents JWT access token claims
type TokenClaims struct {
	Username     string `json:"username"`
	Role         string `json:"role"`
	SessionID    uint   `json:"session_id"`
	RefreshToken string `json:"refresh_token"`
	jwt.RegisteredClaims
}

// JWT secret key - should be set via environment variable
var jwtKey []byte

// InitJWTKey initializes the JWT key from environment variable
func InitJWTKey() {
	jwtKey = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtKey) == 0 {
		log.Fatal("JWT_SECRET environment variable is required")
	}
}

// GetJWTKey returns the JWT key
func GetJWTKey() []byte {
	return jwtKey
}

// LoginResponse represents the response for login requests
type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Role         string `json:"role"`
	Username     string `json:"username"`
}

// Login	godoc
// @Summary User login
// @Description Authenticate user and return JWT tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Param username body string true "Username"
// @Param password body string true "Password"
// @Success 200 {object} LoginResponse "Successful login with tokens"
// @Failure 400 {object} ErrorResponse "Invalid request format"
// @Failure 401 {object} ErrorResponse "Invalid credentials"
// @Failure 500 {object} ErrorResponse "Server error"
// @Router /auth/login [post]
func Login(c *gin.Context) {
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
	
	user, authenticated := AuthenticateUser(credentials.Username, credentials.Password)
	if !authenticated {
		log.Printf("Authentication failed for user: %s", credentials.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	log.Printf("Authentication successful for user: %s", credentials.Username)
	
	// Generate access token and refresh token
	accessToken, refreshToken, err := GenerateTokens(user)
	if err != nil {
		log.Printf("Failed to generate tokens for user %s: %v", user.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
		return
	}

	response := LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(AccessTokenExpiry.Seconds()),
		Role:         string(user.Role),
		Username:     user.Username,
	}

	c.JSON(http.StatusOK, response)
	
	log.Printf("Login successful for user: %s, tokens generated", user.Username)
}

// Register\tgodoc\n// @Summary User registration\n// @Description Register a new user account\n// @Tags Authentication\n// @Accept json\n// @Produce json\n// @Param registerInfo body struct{Username string \"json:\\\"username\\\"\";Email string \"json:\\\"email\\\"\";Password string \"json:\\\"password\\\"\"} true \"Registration info\"\n// @Success 201 {object} SuccessResponse \"User registered successfully\"\n// @Failure 400 {object} ErrorResponse \"Invalid request format\"\n// @Failure 409 {object} ErrorResponse \"User already exists\"\n// @Failure 500 {object} ErrorResponse \"Server error\"\n// @Router /auth/register [post]\nfunc Register(c *gin.Context) {\n
	var userData struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&userData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if user already exists
	var existingUser models.User
	if err := database.DB.Where("username = ? OR email = ?", userData.Username, userData.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User with this username or email already exists"})
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	// Create new user with default 'user' role (not admin)
	newUser := models.User{
		Username: userData.Username,
		Email:    userData.Email,
		Password: string(hashedPassword),
		Role:     models.RoleUser, // Explicitly set to user role only
	}

	if err := database.DB.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":  "User registered successfully",
		"username": newUser.Username,
		"role":     string(newUser.Role),
	})
}

// RefreshToken\tgodoc\n// @Summary Refresh JWT token\n// @Description Refresh access token using refresh token\n// @Tags Authentication\n// @Accept json\n// @Produce json\n// @Param tokenInfo body struct{RefreshToken string \"json:\\\"refresh_token\\\"\"} true \"Refresh token info\"\n// @Success 200 {object} LoginResponse \"New tokens returned\"\n// @Failure 400 {object} ErrorResponse \"Invalid request format\"\n// @Failure 401 {object} ErrorResponse \"Invalid refresh token\"\n// @Failure 500 {object} ErrorResponse \"Server error\"\n// @Router /auth/refresh [post]\nfunc RefreshToken(c *gin.Context) {\n\tvar req struct {\n\t\tRefreshToken string `json:\"refresh_token\"`\n\t}\n\n\tif err := c.ShouldBindJSON(&req); err != nil {\n\t\tc.JSON(http.StatusBadRequest, ErrorResponse{Error: \"Invalid request format\"})\n\t\treturn\n\t}\n\n\t// Validate refresh token\n\tclaims, err := utils.ParseRefreshToken(req.RefreshToken)\n\tif err != nil {\n\t\tc.JSON(http.StatusUnauthorized, ErrorResponse{Error: \"Invalid refresh token\"})\n\t\treturn\n\t}\n\n\t// Generate new tokens\n\tuserID := claims.UserID\n\tnewAccessToken, newRefreshToken, err := utils.GenerateTokens(userID)\n\tif err != nil {\n\t\tc.JSON(http.StatusInternalServerError, ErrorResponse{Error: \"Server error\"})\n\t\treturn\n\t}\n\n\t// Update refresh token in database\n\tif err := database.UpdateRefreshToken(userID, newRefreshToken); err != nil {\n\t\tc.JSON(http.StatusInternalServerError, ErrorResponse{Error: \"Server error\"})\n\t\treturn\n\t}\n\n\tc.JSON(http.StatusOK, LoginResponse{\n\t\tAccessToken:  newAccessToken,\n\t\tTokenType:    \"Bearer\",\n\t\tRefreshToken: newRefreshToken,\n\t})\n}
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

	// Generate new tokens
	newAccessToken, newRefreshToken, err := GenerateTokens(&user) // Pass the user with correct role
	if err != nil {
		log.Printf("Failed to generate new tokens: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate new tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
		"expires_in":    int64(AccessTokenExpiry.Seconds()),
		"role":          string(user.Role), // Use the user's actual role
		"username":      user.Username,
	})
}

// GenerateTokens generates both access and refresh tokens
func GenerateTokens(user *models.User) (string, string, error) {
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

	// Generate access token using user's actual role
	accessToken, err := GenerateAccessToken(user.ID, user.Username, string(user.Role), session.ID, refreshToken)
	if err != nil {
		// If access token generation fails, remove the session
		database.DB.Delete(&session)
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// GenerateAccessToken generates a JWT access token
func GenerateAccessToken(userID uint, username, role string, sessionID uint, refreshToken string) (string, error) {
	// Set token expiration time (15 minutes)
	expirationTime := time.Now().Add(AccessTokenExpiry)
	claims := &TokenClaims{
		Username:     username,
		Role:         role,
		SessionID:    sessionID,
		RefreshToken: refreshToken,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID), // Store user ID as subject for validation
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

// AuthenticateUser authenticates a user against the database
func AuthenticateUser(username, password string) (*models.User, bool) {
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

// SessionTimeout defines how long a user can be inactive before being logged out
const SessionTimeout = 30 * time.Minute // 30 minutes of inactivity

// AccessTokenExpiry defines how long the JWT access token is valid
const AccessTokenExpiry = 15 * time.Minute // 15 minutes

// RefreshTokenExpiry defines how long the refresh token is valid (absolute max)
const RefreshTokenExpiry = 30 * 24 * time.Hour // 30 days