package aws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gin-gonic/gin"
)

var ec2Client *ec2.Client
var instanceID string

// InitAWS initializes AWS clients with IAM Roles Anywhere support
func InitAWS() {
	// Get the instance ID from environment variable
	instanceID = os.Getenv("VPN_INSTANCE_ID")
	if instanceID == "" {
		log.Fatal("VPN_INSTANCE_ID environment variable is required")
	}

	// Load client certificate and key for IAM Roles Anywhere
	certFile := "/etc/ssl/certs/webapp/tls.crt"
	keyFile := "/etc/ssl/certs/webapp/tls.key"

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load client certificate: %v", err)
	}

	// Load CA certificate
	caCertFile := "/etc/ssl/certs/webapp/ca.crt"
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create custom HTTP client with client certificate for IAM Roles Anywhere
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caCertPool,
			},
		},
	}

	// Load AWS configuration with IAM Roles Anywhere support
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(os.Getenv("AWS_REGION")),
		config.WithHTTPClient(httpClient),
	)
	if err != nil {
		log.Printf("Warning: unable to load AWS SDK config, %v", err)
		// We'll try to create the client anyway, but operations will fail
	}

	// Create STS client
	stsClient := sts.NewFromConfig(cfg)

	// Create credentials using IAM Roles Anywhere
	// The role ARN is determined by the trust policy in the IAM Roles Anywhere profile
	creds := stscreds.NewAssumeRoleProvider(stsClient, "unused-parameter")

	// Create EC2 client with the assumed role credentials
	ec2Client = ec2.NewFromConfig(cfg, func(o *ec2.Options) {
		o.Credentials = aws.NewCredentialsCache(creds)
		o.HTTPClient = httpClient
	})
}

// StartInstance	godoc
// @Summary Start VPN instance
// @Description Start the VPN EC2 instance
// @Tags VPN Management
// @Produce json
// @Success 200 {object} types.SuccessResponse "Instance start command sent"
// @Failure 500 {object} types.ErrorResponse "Failed to start instance"
// @Router /start [post]
func StartInstance(c *gin.Context) {
	if ec2Client == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AWS client not initialized"})
		return
	}

	input := &ec2.StartInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.StartInstances(context.TODO(), input)
	if err != nil {
		log.Printf("Failed to start instance %s: %v", instanceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to start instance: %v", err)})
		return
	}

	log.Printf("Start instance result: %v", result)
	if len(result.StartingInstances) > 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": "Instance start command sent",
			"state":   result.StartingInstances[0].CurrentState.Name,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message": "Instance start command sent",
			"state":   "unknown",
		})
	}
}

// StopInstance	godoc
// @Summary Stop VPN instance
// @Description Stop the VPN EC2 instance
// @Tags VPN Management
// @Produce json
// @Success 200 {object} types.SuccessResponse "Instance stop command sent"
// @Failure 500 {object} types.ErrorResponse "Failed to stop instance"
// @Router /stop [post]
func StopInstance(c *gin.Context) {
	if ec2Client == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AWS client not initialized"})
		return
	}

	input := &ec2.StopInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.StopInstances(context.TODO(), input)
	if err != nil {
		log.Printf("Failed to stop instance %s: %v", instanceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to stop instance: %v", err)})
		return
	}

	log.Printf("Stop instance result: %v", result)
	if len(result.StoppingInstances) > 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": "Instance stop command sent",
			"state":   result.StoppingInstances[0].CurrentState.Name,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message": "Instance stop command sent",
			"state":   "unknown",
		})
	}
}

// GetInstanceStatus	godoc
// @Summary Get VPN instance status
// @Description Get the current status of the VPN EC2 instance
// @Tags VPN Management
// @Produce json
// @Success 200 {object} types.StatusResponse "Instance status with state and name"
// @Failure 404 {object} types.ErrorResponse "Instance not found"
// @Failure 500 {object} types.ErrorResponse "Failed to get instance status"
// @Router /status [get]
func GetInstanceStatus(c *gin.Context) {
	if ec2Client == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AWS client not initialized"})
		return
	}

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.DescribeInstances(context.TODO(), input)
	if err != nil {
		log.Printf("Failed to get instance status %s: %v", instanceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get instance status: %v", err)})
		return
	}

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
		return
	}

	instanceState := result.Reservations[0].Instances[0].State.Name
	c.JSON(http.StatusOK, gin.H{
		"state": string(instanceState),
		"name":  instanceID,
	})
}
