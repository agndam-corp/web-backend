package models

import (
	"gorm.io/gorm"
	"time"
)

// Role represents user roles in the system
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// User represents a user in the system
type User struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	Username  string         `gorm:"uniqueIndex;not null" json:"username"`
	Email     string         `gorm:"uniqueIndex;not null" json:"email"`
	Password  string         `gorm:"column:password_hash;not null" json:"-"` // Don't expose password hash
	Role      Role           `gorm:"default:user;not null" json:"role"`     // Default to user role
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Sessions relationship
	Sessions []Session `json:"sessions,omitempty"`
}

// Session represents a user session with refresh token
type Session struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	UserID       uint   `gorm:"not null" json:"user_id"`
	RefreshToken string `gorm:"uniqueIndex;not null" json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `gorm:"autoUpdateTime" json:"last_activity"`

	// User relationship
	User User `json:"user,omitempty"`
}

// TableName overrides the table name for User
func (User) TableName() string {
	return "users"
}

// TableName overrides the table name for Session
func (Session) TableName() string {
	return "sessions"
}