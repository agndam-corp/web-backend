package models

import (
	"time"

	"gorm.io/gorm"
)

// AWSInstance represents an AWS EC2 instance configuration
type AWSInstance struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	Name        string         `gorm:"not null" json:"name"`
	InstanceID  string         `gorm:"uniqueIndex;not null" json:"instanceId"`
	Region      string         `gorm:"not null" json:"region"`
	Description string         `json:"description,omitempty"`
	Status      string         `json:"status,omitempty"`          // current status: running, stopped, etc.
	CreatedBy   uint           `gorm:"not null" json:"createdBy"` // User ID who created this instance
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`

	// User relationship - the user who created this instance
	CreatedByUser User `json:"createdByUser,omitempty" gorm:"foreignKey:CreatedBy"`
}
