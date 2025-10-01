package aws

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/gin-gonic/gin"
)

// TestIAMAnywhereEndpoint godoc
//
//	@Summary		Test IAM Anywhere connection
//	@Description	Test endpoint that uses the exact same AWS configuration as the working test
//	@Tags			VPN Management
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"Test results"
//	@Failure		500	{object}	map[string]string		"Error message"
//	@Router			/test-iam-anywhere [get]
func TestIAMAnywhereEndpoint(c *gin.Context) {
	awsProfile := os.Getenv("AWS_PROFILE")
	if awsProfile == "" {
		awsProfile = "rolesanywhere-profile"
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	log.Printf("Testing AWS connection with profile: %s, region: %s", awsProfile, region)

	// Load AWS config using the same approach as the working test
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithSharedConfigProfile(awsProfile),
		config.WithRegion(region),
	)
	if err != nil {
		log.Printf("Failed to load AWS config: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to load AWS config: %v", err)})
		return
	}

	log.Printf("AWS Config loaded successfully. Region: %s", cfg.Region)
	log.Printf("AWS Config loaded successfully. EndpointResolver: %v", cfg.EndpointResolver)
	log.Printf("AWS Config loaded successfully. Credentials: %v", cfg.Credentials)

	ec2Client := ec2.NewFromConfig(cfg)

	// Describe instances
	log.Println("Attempting to describe EC2 instances...")
	output, err := ec2Client.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
		MaxResults: aws.Int32(5),
	})
	if err != nil {
		log.Printf("DescribeInstances failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("DescribeInstances failed: %v", err)})
		return
	}

	log.Printf("Successfully connected! Found %d reservations.", len(output.Reservations))
	
	// Prepare response data
	var instances []map[string]interface{}
	for i, r := range output.Reservations {
		log.Printf("Reservation %d: %d instances", i+1, len(r.Instances))
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
			log.Printf("  Instance %d: %s - %s", j+1, instance["instanceId"], instance["state"])
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      "success",
		"message":     "Successfully connected to AWS!",
		"reservations": len(output.Reservations),
		"instances":   instances,
	})
}