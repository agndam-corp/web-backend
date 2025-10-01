package aws

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

var (
	defaultRegion  string
	defaultProfile string
	ec2Client      *ec2.Client
)

// InitAWS initializes AWS configuration and EC2 client with IAM Roles Anywhere support
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
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithSharedConfigProfile(defaultProfile),
		config.WithRegion(defaultRegion),
	)
	if err != nil {
		log.Fatalf("Failed to load AWS config with profile %s: %v", defaultProfile, err)
	}

	// Create EC2 client with the loaded config
	ec2Client = ec2.NewFromConfig(cfg)

	// Log credential information to ensure IAM Anywhere provider is loaded
	creds, credErr := cfg.Credentials.Retrieve(context.Background())
	if credErr != nil {
		log.Printf("Failed to retrieve credentials: %v", credErr)
	} else {
		log.Printf("Credentials loaded successfully. AccessKeyID: %s, ProviderName: %s, Expires: %v", 
			creds.AccessKeyID[:min(8, len(creds.AccessKeyID))] + "...", creds.Source, creds.Expires)
	}

	log.Printf("AWS configuration and EC2 client initialized successfully for profile: %s, region: %s", defaultProfile, defaultRegion)
}

// GetEC2Client returns the initialized EC2 client
func GetEC2Client() *ec2.Client {
	if ec2Client == nil {
		log.Fatal("AWS EC2 client not initialized. Call InitAWS() first.")
	}
	return ec2Client
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}