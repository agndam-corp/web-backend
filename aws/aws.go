package aws

import (
	"context"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/gin-gonic/gin"
)

var (
	defaultRegion  string
	defaultProfile string
	once           sync.Once
)

// InitAWS sets up default region and profile. Safe to call multiple times.
func InitAWS() {
	once.Do(func() {
		defaultRegion = os.Getenv("AWS_REGION")
		if defaultRegion == "" {
			defaultRegion = "us-east-1"
		}

		defaultProfile = os.Getenv("AWS_PROFILE")
		if defaultProfile == "" {
			defaultProfile = "rolesanywhere-profile"
		}

		log.Printf("AWS initialized with profile=%s region=%s", defaultProfile, defaultRegion)
	})
}

// getEC2Client creates a new EC2 client for the given region
func getEC2Client(ctx context.Context, region string) (*ec2.Client, error) {
	if region == "" {
		region = defaultRegion
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(defaultProfile),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, err
	}

	// Test credentials
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		log.Printf("Failed to retrieve credentials: %v", err)
	} else {
		log.Printf("Credentials loaded: AccessKeyID=%s..., ProviderName=%s, Expires=%v",
			creds.AccessKeyID[:8], creds.Source, creds.Expires)
	}

	// Explicitly set EC2 endpoint to avoid ResolveEndpointV2 errors
	client := ec2.NewFromConfig(cfg, func(o *ec2.Options) {
		o.EndpointResolver = ec2.EndpointResolverFromURL("https://ec2." + region + ".amazonaws.com")
	})

	return client, nil
}

// DescribeInstances lists up to 5 EC2 instances in the specified region
func DescribeInstances(ctx context.Context, region string) error {
	client, err := getEC2Client(ctx, region)
	if err != nil {
		return err
	}

	output, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		MaxResults: aws.Int32(5),
	})
	if err != nil {
		return err
	}

	log.Printf("Found %d reservations", len(output.Reservations))
	for i, r := range output.Reservations {
		for j, inst := range r.Instances {
			id := "unknown"
			state := "unknown"
			if inst.InstanceId != nil {
				id = *inst.InstanceId
			}
			if inst.State != nil {
				state = string(inst.State.Name)
			}
			log.Printf("Reservation %d - Instance %d: %s (%s)", i+1, j+1, id, state)
		}
	}

	return nil
}

// TestIAMAnywhereEndpoint handles /test-iam-anywhere route
func TestIAMAnywhereEndpoint(c *gin.Context) {
	client, err := getEC2Client(c.Request.Context(), "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": err.Error()})
		return
	}

	output, err := client.DescribeInstances(c.Request.Context(), &ec2.DescribeInstancesInput{
		MaxResults: aws.Int32(5),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": err.Error()})
		return
	}

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
