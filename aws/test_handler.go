package aws

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
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
	// Use the global EC2 client that was initialized at startup
	ec2Client := GetEC2Client()

	log.Printf("Using pre-initialized EC2 client for region: %s with profile: %s", defaultRegion, defaultProfile)

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