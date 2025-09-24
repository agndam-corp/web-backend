package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

func main() {
	// Set Gin to release mode
	gin.SetMode(gin.ReleaseMode)

	// Create router
	router := gin.Default()

	// Add CORS middleware for all routes
	router.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin == "https://djasko.com" || origin == "http://localhost:3000" {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Requested-With")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})

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

	// Add basic auth middleware for protected routes
	authorized := router.Group("/", gin.BasicAuth(gin.Accounts{
		os.Getenv("BASIC_AUTH_USERNAME"): os.Getenv("BASIC_AUTH_PASSWORD"),
	}))

	// Health check endpoint (no auth required)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Simple auth check endpoint (no AWS interaction)
	router.GET("/auth-check", func(c *gin.Context) {
		// This is just to verify that basic auth is working
		// We don't actually do anything with the credentials here
		c.JSON(http.StatusOK, gin.H{"authenticated": true})
	})

	// Define protected routes that interact with AWS
	authorized.POST("/start", startInstance)
	authorized.POST("/stop", stopInstance)
	authorized.GET("/status", getInstanceStatus)

	// Start server
	router.Run(":8080")
}

func startInstance(c *gin.Context) {
	if ec2Client == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AWS client not initialized"})
		return
	}

	input := &ec2.StartInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.StartInstances(context.TODO(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Instance start initiated",
		"result":  result,
	})
}

func stopInstance(c *gin.Context) {
	if ec2Client == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AWS client not initialized"})
		return
	}

	input := &ec2.StopInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.StopInstances(context.TODO(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Instance stop initiated",
		"result":  result,
	})
}

func getInstanceStatus(c *gin.Context) {
	if ec2Client == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "AWS client not initialized"})
		return
	}

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.DescribeInstances(context.TODO(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
		return
	}

	instance := result.Reservations[0].Instances[0]
	c.JSON(http.StatusOK, gin.H{
		"instanceId":   *instance.InstanceId,
		"state":        string(instance.State.Name),
		"instanceType": string(instance.InstanceType),
	})
}