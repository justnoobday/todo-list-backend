package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Models
type User struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Username  string    `json:"username" gorm:"unique;not null"`
	Email     string    `json:"email" gorm:"unique;not null"`
	Password  string    `json:"-" gorm:"not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Tasks     []Task    `json:"tasks,omitempty" gorm:"foreignKey:UserID"`
}

type Task struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Title       string    `json:"title" gorm:"not null;size:255"`
	Description string    `json:"description" gorm:"type:text"`
	Status      string    `json:"status" gorm:"default:pending"`
	UserID      uint      `json:"user_id" gorm:"not null"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type RefreshToken struct {
	ID        uint      `gorm:"primaryKey"`
	Token     string    `gorm:"unique;not null"`
	UserID    uint      `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}

// Request/Response structs
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type CreateTaskRequest struct {
	Title       string `json:"title" binding:"required,max=255"`
	Description string `json:"description"`
}

type UpdateTaskRequest struct {
	Title       string `json:"title" binding:"max=255"`
	Description string `json:"description"`
	Status      string `json:"status" binding:"omitempty,oneof=pending completed"`
}

type AuthResponse struct {
	User         User   `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// JWT Claims
type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

// Global variables
var (
	db        *gorm.DB
	jwtSecret []byte
)

// Database initialization
func initDatabase() {
	// Get database configuration from environment variables
	host := os.Getenv("DB_HOST")
	if host == "" {
		host = "localhost"
	}

	port := os.Getenv("DB_PORT")
	if port == "" {
		port = "5432"
	}

	user := os.Getenv("DB_USER")
	if user == "" {
		user = "postgres"
	}

	password := os.Getenv("DB_PASSWORD")
	if password == "" {
		log.Fatal("DB_PASSWORD environment variable is required")
	}

	dbname := os.Getenv("DB_NAME")
	if dbname == "" {
		dbname = "todoapp"
	}

	sslmode := os.Getenv("DB_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}

	timezone := os.Getenv("DB_TIMEZONE")
	if timezone == "" {
		timezone = "Asia/Jakarta"
	}

	// Create PostgreSQL connection string
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		host, user, password, dbname, port, sslmode, timezone)

	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to PostgreSQL database:", err)
	}

	// Test the connection
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatal("Failed to get database instance:", err)
	}

	if err := sqlDB.Ping(); err != nil {
		log.Fatal("Failed to ping database:", err)
	}

	// Configure connection pool
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Auto migrate schemas
	err = db.AutoMigrate(&User{}, &Task{}, &RefreshToken{})
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	log.Println("Successfully connected to PostgreSQL database")
}

// JWT Helper functions
func generateTokens(userID uint) (string, string, error) {
	// Access token (15 minutes)
	accessClaims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	// Refresh token (7 days)
	refreshClaims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	// Store refresh token in database
	dbRefreshToken := RefreshToken{
		Token:     refreshTokenString,
		UserID:    userID,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	db.Create(&dbRefreshToken)

	return accessTokenString, refreshTokenString, nil
}

func validateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrInvalidKey
}

// Middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to get token from cookie first
		tokenString, err := c.Cookie("access_token")
		if err != nil {
			// If no cookie, try Authorization header
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "No authorization token provided"})
				c.Abort()
				return
			}

			// Extract token from "Bearer <token>"
			tokenParts := strings.Split(authHeader, " ")
			if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
				c.Abort()
				return
			}
			tokenString = tokenParts[1]
		}

		claims, err := validateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Next()
	}
}

// Handlers
func register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if user already exists
	var existingUser User
	if err := db.Where("email = ? OR username = ?", req.Email, req.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User with this email or username already exists"})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Create user
	user := User{
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
	}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Generate tokens
	accessToken, refreshToken, err := generateTokens(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// Set secure HTTP-only cookies
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("access_token", accessToken, 15*60, "/", "", false, true)        // 15 minutes
	c.SetCookie("refresh_token", refreshToken, 7*24*60*60, "/", "", false, true) // 7 days

	c.JSON(http.StatusCreated, AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find user
	var user User
	if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate tokens
	accessToken, refreshToken, err := generateTokens(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// Set secure HTTP-only cookies
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("access_token", accessToken, 15*60, "/", "", false, true)        // 15 minutes
	c.SetCookie("refresh_token", refreshToken, 7*24*60*60, "/", "", false, true) // 7 days

	c.JSON(http.StatusOK, AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func refreshToken(c *gin.Context) {
	// Get refresh token from cookie
	refreshTokenString, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token provided"})
		return
	}

	// Validate refresh token
	claims, err := validateToken(refreshTokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Check if refresh token exists in database
	var dbRefreshToken RefreshToken
	if err := db.Where("token = ? AND user_id = ?", refreshTokenString, claims.UserID).First(&dbRefreshToken).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Delete old refresh token
	db.Delete(&dbRefreshToken)

	// Generate new tokens
	accessToken, newRefreshToken, err := generateTokens(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// Set new cookies
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("access_token", accessToken, 15*60, "/", "", false, true)
	c.SetCookie("refresh_token", newRefreshToken, 7*24*60*60, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}

func logout(c *gin.Context) {
	// Get refresh token from cookie
	refreshTokenString, err := c.Cookie("refresh_token")
	if err == nil {
		// Delete refresh token from database
		db.Where("token = ?", refreshTokenString).Delete(&RefreshToken{})
	}

	// Clear cookies
	c.SetCookie("access_token", "", -1, "/", "", false, true)
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func getTasks(c *gin.Context) {
	userID := c.GetUint("user_id")

	var tasks []Task
	if err := db.Where("user_id = ?", userID).Order("created_at DESC").Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tasks"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

func createTask(c *gin.Context) {
	userID := c.GetUint("user_id")

	var req CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task := Task{
		Title:       req.Title,
		Description: req.Description,
		Status:      "pending",
		UserID:      userID,
	}

	if err := db.Create(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create task"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"task": task})
}

func getTask(c *gin.Context) {
	userID := c.GetUint("user_id")
	taskID := c.Param("id")

	var task Task
	if err := db.Where("id = ? AND user_id = ?", taskID, userID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"task": task})
}

func updateTask(c *gin.Context) {
	userID := c.GetUint("user_id")
	taskID := c.Param("id")

	var task Task
	if err := db.Where("id = ? AND user_id = ?", taskID, userID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	var req UpdateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update fields if provided
	if req.Title != "" {
		task.Title = req.Title
	}
	if req.Description != "" {
		task.Description = req.Description
	}
	if req.Status != "" {
		task.Status = req.Status
	}

	if err := db.Save(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"task": task})
}

func deleteTask(c *gin.Context) {
	userID := c.GetUint("user_id")
	taskID := c.Param("id")

	var task Task
	if err := db.Where("id = ? AND user_id = ?", taskID, userID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	if err := db.Delete(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task deleted successfully"})
}

func getCurrentUser(c *gin.Context) {
	userID := c.GetUint("user_id")

	var user User
	if err := db.Preload("Tasks").Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": user})
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using default values")
	}

	// Set JWT secret
	jwtSecretString := os.Getenv("JWT_SECRET")
	if jwtSecretString == "" {
		jwtSecretString = "your-secret-key-change-this-in-production"
		log.Println("Warning: Using default JWT secret. Set JWT_SECRET environment variable in production.")
	}
	jwtSecret = []byte(jwtSecretString)

	// Initialize database
	initDatabase()

	// Initialize Gin router
	r := gin.Default()

	// CORS middleware (basic)
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "http://localhost:5173") // Change this to your frontend URL
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "timestamp": time.Now()})
	})

	// Auth routes
	auth := r.Group("/api/auth")
	{
		auth.POST("/register", register)
		auth.POST("/login", login)
		auth.POST("/refresh", refreshToken)
		auth.POST("/logout", logout)
		auth.GET("/me", authMiddleware(), getCurrentUser)
	}

	// Task routes (protected)
	tasks := r.Group("/api/tasks")
	tasks.Use(authMiddleware())
	{
		tasks.GET("", getTasks)
		tasks.POST("", createTask)
		tasks.GET("/:id", getTask)
		tasks.PUT("/:id", updateTask)
		tasks.DELETE("/:id", deleteTask)
	}

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(r.Run(":" + port))
}
