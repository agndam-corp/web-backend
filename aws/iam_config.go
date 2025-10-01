package aws

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type Config = aws.Config

var (
	defaultRegion string
	defaultProfile string
	cfg aws.Config
)

// InitAWS initializes AWS configuration with IAM Roles Anywhere support
func InitAWS() {
	// Get the default region from environment variable
	defaultRegion = os.Getenv("AWS_REGION")
	if defaultRegion == "" {
		defaultRegion = "us-east-1" // Default to us-east-1 if not specified
	}

	// Get the AWS profile name from environment variable
	defaultProfile = os.Getenv("AWS_PROFILE")
	if defaultProfile == "" {
		defaultProfile = "rolesanywhere-profile" // Use the Roles Anywhere profile by default
	}

	log.Printf("Initializing AWS with profile: %s, region: %s", defaultProfile, defaultRegion)

	// Load AWS config using credential_process for IAM Roles Anywhere
	var err error
	cfg, err = config.LoadDefaultConfig(context.Background(),
		config.WithSharedConfigProfile(defaultProfile),
		config.WithRegion(defaultRegion),
	)
	if err != nil {
		log.Fatalf("Failed to load AWS config with profile %s: %v", defaultProfile, err)
	}

	log.Printf("AWS configuration initialized successfully for profile: %s, region: %s", defaultProfile, defaultRegion)
}

// GetAWSConfig returns the initialized AWS configuration
func GetAWSConfig() aws.Config {
	return cfg
}