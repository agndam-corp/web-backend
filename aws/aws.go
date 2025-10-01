package aws

import (
	"net/http"
	"context"
	"log"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/gin-gonic/gin"
)

// Package-level variables
var (
	ec2Client     *ec2.Client
	defaultRegion string
	defaultProfile string
	once          sync.Once
)

// InitAWS initializes AWS SDK using IAM Roles Anywhere profile.
// It is safe to call multiple times; initialization happens only once.
func InitAWS() {
	once.Do(func() {
		// Default region
		defaultRegion = os.Getenv("AWS_REGION")
		if defaultRegion == "" {
			defaultRegion = "us-east-1"
		}

		// AWS profile for IAM Roles Anywhere
		defaultProfile = os.Getenv("AWS_PROFILE")
		if defaultProfile == "" {
			defaultProfile = "rolesanywhere-profile"
		}

		log.Printf("Initializing AWS SDK with profile '%s' and region '%s'", defaultProfile, defaultRegion)

		// Load config using shared config and credential_process
		cfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithSharedConfigProfile(defaultProfile),
			config.WithRegion(defaultRegion),
		)
		if err != nil {
			log.Fatalf("Failed to load AWS config: %v", err)
		}

		// Create EC2 client
		ec2Client = ec2.NewFromConfig(cfg)

		// Test credentials
		creds, err := cfg.Credentials.Retrieve(context.Background())
		if err != nil {
			log.Fatalf("Failed to retrieve IAM Anywhere credentials: %v", err)
		}

		log.Printf("AWS credentials loaded: AccessKeyID=%s..., ProviderName=%s, Expires=%v",
			creds.AccessKeyID[:8], creds.Source, creds.Expires)
	})
}

// GetEC2Client returns the initialized EC2 client
func GetEC2Client() *ec2.Client {
	if ec2Client == nil {
		log.Fatal("EC2 client not initialized. Call InitAWS() first.")
	}
	return ec2Client
}

// Example helper function: Describe up to 5 EC2 instances
func DescribeInstances(ctx context.Context) {
	client := GetEC2Client()
	output, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		MaxResults: aws.Int32(5),
	})
	if err != nil {
		log.Fatalf("DescribeInstances failed: %v", err)
	}

	log.Printf("Found %d reservations", len(output.Reservations))
	for i, r := range output.Reservations {
		log.Printf("Reservation %d: %d instances", i+1, len(r.Instances))
		for j, inst := range r.Instances {
			id := "unknown"
			state := "unknown"
			if inst.InstanceId != nil {
				id = *inst.InstanceId
			}
			if inst.State != nil {
				state = string(inst.State.Name)
			}
			log.Printf("  Instance %d: %s - %s", j+1, id, state)
		}
	}
}

// TestIAMAnywhereEndpoint handles /test-iam-anywhere route
func TestIAMAnywhereEndpoint(c *gin.Context) {
	client := GetEC2Client()

	output, err := client.DescribeInstances(c.Request.Context(), &ec2.DescribeInstancesInput{
		MaxResults: aws.Int32(5),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	// Build structured response
	var instances []map[string]interface{}
	for i, r := range output.Reservations {
		for j, inst := range r.Instances {
			instance := map[string]interface{}{
				"reservation": i + 1,
				"instance":    j + 1,
			}
			if inst.InstanceId != nil {
				instance["instanceId"] = *inst.InstanceId
			} else {
				instance["instanceId"] = "unknown"
			}
			if inst.State != nil {
				instance["state"] = string(inst.State.Name)
			} else {
				instance["state"] = "unknown"
			}
			instances = append(instances, instance)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"reservations": len(output.Reservations),
		"instances":    instances,
	})
}