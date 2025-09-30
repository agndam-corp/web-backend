/*
Package aws provides AWS EC2 instance management functionality.

This package handles the management of AWS EC2 instances including:
- Starting, stopping, and checking the status of EC2 instances
- Managing instance configurations in the database
- Supporting multi-region AWS operations
- Providing admin-level instance management capabilities

# API Endpoints

## Instance Operations

### Start Instance

	POST /start
	Starts an EC2 instance. Accepts instanceId and region in request body.

### Stop Instance

	POST /stop
	Stops an EC2 instance. Accepts instanceId and region in request body.

### Get Instance Status

	GET /status?instanceId=...&region=...
	Gets the status of an EC2 instance. Accepts instanceId and region as query parameters.

## Instance Management

### List Instances (User)

	GET /instances
	Get all instances owned by the current user.

### Get Instance (User)

	GET /instances/:id
	Get a specific instance by ID.

### Create Instance (User)

	POST /instances
	Create a new instance configuration.

### Update Instance (User)

	PUT /instances/:id
	Update an existing instance configuration.

### Delete Instance (User)

	DELETE /instances/:id
	Delete an instance configuration.

## Admin Instance Management

### Create Instance (Admin)

	POST /admin/instances
	Admin endpoint to create an instance for any user.

### Update Instance (Admin)

	PUT /admin/instances/:id
	Admin endpoint to update any instance.

### Delete Instance (Admin)

	DELETE /admin/instances/:id
	Admin endpoint to delete any instance.

## Request/Response Examples

### Start/Stop Instance Request

	{
	  "instanceId": "i-1234567890abcdef0",
	  "region": "us-west-2"
	}

### Instance Status Response

	{
	  "state": "running",
	  "name": "i-1234567890abcdef0",
	  "region": "us-west-2"
	}

### List Instances Response

	[
	  {
	    "id": 1,
	    "name": "My VPN Server",
	    "instanceId": "i-1234567890abcdef0",
	    "region": "us-west-2",
	    "description": "Primary VPN server",
	    "status": "running",
	    "createdBy": 1,
	    "createdAt": "2023-01-01T00:00:00Z",
	    "updatedAt": "2023-01-01T00:00:00Z"
	  }
	]
*/
package aws

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/agndam-corp/web-backend/database"
	"github.com/agndam-corp/web-backend/models"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var defaultInstanceID string
var defaultRegion string
var defaultProfile string
var defaultHTTPClient *http.Client

// InstanceRequest represents the request body for AWS instance operations
type InstanceRequest struct {
	InstanceID string `json:"instanceId" form:"instanceId"`
	Region     string `json:"region" form:"region"`
}

// loadAWSConfig loads AWS configuration with support for IAM Roles Anywhere
func loadAWSConfig(region string) (aws.Config, error) {
	// Primary attempt: Load config from specific paths where it's mounted in k8s
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithSharedConfigProfile(defaultProfile),
		config.WithRegion(region),
		config.WithSharedConfigFiles([]string{"/root/.aws/config", "/root/.aws/credentials"}), // Explicit paths where k8s mounts config
	)
	if err != nil {
		log.Printf("Failed to load AWS config for region %s from explicit paths: %v", region, err)
		// Fallback to default config loading if explicit paths fail
		cfg, err = config.LoadDefaultConfig(context.TODO(),
			config.WithSharedConfigProfile(defaultProfile),
			config.WithRegion(region),
		)
		if err != nil {
			log.Printf("Failed to load AWS config with profile %s for region %s: %v", defaultProfile, region, err)
			return cfg, fmt.Errorf("failed to load AWS config for region %s: %w", region, err)
		}
	} else {
		log.Printf("Successfully loaded AWS config from explicit paths for region: %s", region)
	}

	return cfg, nil
}

// createEC2ClientForRegion creates an EC2 client for a specific region
func createEC2ClientForRegion(region string) (*ec2.Client, error) {
	if defaultHTTPClient == nil {
		return nil, fmt.Errorf("AWS clients not initialized properly")
	}

	log.Printf("Creating EC2 client for region: %s", region)

	cfg, err := loadAWSConfig(region)
	if err != nil {
		return nil, err
	}

	// Create EC2 client with the region-specific configuration
	ec2Client := ec2.NewFromConfig(cfg)

	return ec2Client, nil
}

// InitAWS initializes AWS clients with support for credential chain including IAM Roles Anywhere
func InitAWS() {
	// Get the default instance ID and region from environment variable
	defaultInstanceID = os.Getenv("VPN_INSTANCE_ID")
	defaultRegion = os.Getenv("AWS_REGION")
	if defaultRegion == "" {
		defaultRegion = "us-east-1" // Default to us-east-1 if not specified
	}
	
	// Get the AWS profile name from environment variable
	defaultProfile = os.Getenv("AWS_PROFILE")
	if defaultProfile == "" {
		defaultProfile = "rolesanywhere-profile"  // Use the Roles Anywhere profile by default
	}
	
	log.Printf("Initializing AWS with profile: %s, region: %s", defaultProfile, defaultRegion)

	// Use the shared function to load config - this ensures consistency
	_, err := loadAWSConfig(defaultRegion)
	if err != nil {
		log.Printf("Failed to load AWS SDK config with profile %s: %v", defaultProfile, err)
		log.Fatalf("Failed to load AWS SDK config: %v", err)
	}

	// Initialize HTTP client
	defaultHTTPClient = &http.Client{}
}

// StartInstance	godoc
//
//	@Summary		Start VPN instance
//	@Description	Start the VPN EC2 instance
//	@Tags			VPN Management
//	@Accept			json
//	@Produce		json
//	@Param			request	body		InstanceRequest			true	"Instance ID and Region"
//	@Success		200		{object}	types.SuccessResponse	"Instance start command sent"
//	@Failure		400		{object}	types.ErrorResponse		"Bad request"
//	@Failure		404		{object}	types.ErrorResponse		"Instance not found in database"
//	@Failure		500		{object}	types.ErrorResponse		"Failed to start instance"
//	@Router			/start [post]
func StartInstance(c *gin.Context) {
	var req InstanceRequest

	// Try to bind JSON first, then form data
	if err := c.ShouldBindJSON(&req); err != nil {
		// If JSON binding fails, try to get from form/query parameters
		c.ShouldBind(&req)
	}

	// Validate required parameters
	if req.InstanceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Instance ID is required"})
		return
	}

	// Check if the instance exists in the database
	var dbInstance models.AWSInstance
	if err := database.DB.Where("instance_id = ?", req.InstanceID).First(&dbInstance).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found in database"})
			return
		}
		log.Printf("Error querying AWS instance from database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Use the region from the database if not provided in request
	if req.Region == "" {
		req.Region = dbInstance.Region
	}

	// Validate region
	if req.Region == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Region is required"})
		return
	}

	// Create EC2 client for the specific region
	ec2Client, err := createEC2ClientForRegion(req.Region)
	if err != nil {
		log.Printf("Failed to create EC2 client for region %s: %v", req.Region, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create AWS client: %v", err)})
		return
	}

	log.Printf("About to start AWS instance %s in region %s", req.InstanceID, req.Region)
	
	input := &ec2.StartInstancesInput{
		InstanceIds: []string{req.InstanceID},
	}

	result, err := ec2Client.StartInstances(context.TODO(), input)
	if err != nil {
		log.Printf("Failed to start instance %s in region %s: %v", req.InstanceID, req.Region, err)
		// Check if error is related to endpoint resolution or credentials
		errMsg := err.Error()
		if strings.Contains(errMsg, "ResolveEndpointV2") ||
			strings.Contains(errMsg, "NoCredentialProviders") ||
			strings.Contains(errMsg, "region") {
			log.Printf("AWS configuration error when starting instance %s: %v", req.InstanceID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("AWS configuration error: %v", err)})
		} else {
			log.Printf("General AWS API error when starting instance %s: %v", req.InstanceID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to start instance: %v", err)})
		}
		return
	}
	
	log.Printf("Successfully sent start command for instance %s", req.InstanceID)

	log.Printf("Start instance result: %v", result)
	if len(result.StartingInstances) > 0 {
		// Update only the status in the database
		if err := database.DB.Model(&dbInstance).Update("Status", string(result.StartingInstances[0].CurrentState.Name)).Error; err != nil {
			log.Printf("Failed to update instance status in database: %v", err)
			// Continue anyway, just log the error
		}

		c.JSON(http.StatusOK, gin.H{
			"message":    "Instance start command sent",
			"state":      string(result.StartingInstances[0].CurrentState.Name),
			"instanceId": req.InstanceID,
			"region":     req.Region,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message":    "Instance start command sent",
			"state":      "unknown",
			"instanceId": req.InstanceID,
			"region":     req.Region,
		})
	}
}

// StopInstance	godoc
//
//	@Summary		Stop VPN instance
//	@Description	Stop the VPN EC2 instance
//	@Tags			VPN Management
//	@Accept			json
//	@Produce		json
//	@Param			request	body		InstanceRequest			true	"Instance ID and Region"
//	@Success		200		{object}	types.SuccessResponse	"Instance stop command sent"
//	@Failure		400		{object}	types.ErrorResponse		"Bad request"
//	@Failure		404		{object}	types.ErrorResponse		"Instance not found in database"
//	@Failure		500		{object}	types.ErrorResponse		"Failed to stop instance"
//	@Router			/stop [post]
func StopInstance(c *gin.Context) {
	var req InstanceRequest

	// Try to bind JSON first, then form data
	if err := c.ShouldBindJSON(&req); err != nil {
		// If JSON binding fails, try to get from form/query parameters
		c.ShouldBind(&req)
	}

	// Validate required parameters
	if req.InstanceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Instance ID is required"})
		return
	}

	// Check if the instance exists in the database
	var dbInstance models.AWSInstance
	if err := database.DB.Where("instance_id = ?", req.InstanceID).First(&dbInstance).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found in database"})
			return
		}
		log.Printf("Error querying AWS instance from database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Use the region from the database if not provided in request
	if req.Region == "" {
		req.Region = dbInstance.Region
	}

	// Validate region
	if req.Region == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Region is required"})
		return
	}

	// Create EC2 client for the specific region
	ec2Client, err := createEC2ClientForRegion(req.Region)
	if err != nil {
		log.Printf("Failed to create EC2 client for region %s: %v", req.Region, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create AWS client: %v", err)})
		return
	}

	log.Printf("About to stop AWS instance %s in region %s", req.InstanceID, req.Region)
	
	input := &ec2.StopInstancesInput{
		InstanceIds: []string{req.InstanceID},
	}

	result, err := ec2Client.StopInstances(context.TODO(), input)
	if err != nil {
		log.Printf("Failed to stop instance %s in region %s: %v", req.InstanceID, req.Region, err)
		// Check if error is related to endpoint resolution or credentials
		errMsg := err.Error()
		if strings.Contains(errMsg, "ResolveEndpointV2") ||
			strings.Contains(errMsg, "NoCredentialProviders") ||
			strings.Contains(errMsg, "region") {
			log.Printf("AWS configuration error when stopping instance %s: %v", req.InstanceID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("AWS configuration error: %v", err)})
		} else {
			log.Printf("General AWS API error when stopping instance %s: %v", req.InstanceID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to stop instance: %v", err)})
		}
		return
	}
	
	log.Printf("Successfully sent stop command for instance %s", req.InstanceID)

	log.Printf("Stop instance result: %v", result)
	if len(result.StoppingInstances) > 0 {
		// Update only the status in the database
		if err := database.DB.Model(&dbInstance).Update("Status", string(result.StoppingInstances[0].CurrentState.Name)).Error; err != nil {
			log.Printf("Failed to update instance status in database: %v", err)
			// Continue anyway, just log the error
		}

		c.JSON(http.StatusOK, gin.H{
			"message":    "Instance stop command sent",
			"state":      string(result.StoppingInstances[0].CurrentState.Name),
			"instanceId": req.InstanceID,
			"region":     req.Region,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message":    "Instance stop command sent",
			"state":      "unknown",
			"instanceId": req.InstanceID,
			"region":     req.Region,
		})
	}
}

// GetInstanceStatus	godoc
//
//	@Summary		Get VPN instance status
//	@Description	Get the current status of the VPN EC2 instance
//	@Tags			VPN Management
//	@Produce		json
//	@Param			instanceId	query		string					false	"Instance ID"
//	@Param			region		query		string					false	"AWS Region"
//	@Success		200			{object}	types.StatusResponse	"Instance status with state and name"
//	@Failure		400			{object}	types.ErrorResponse		"Bad request"
//	@Failure		404			{object}	types.ErrorResponse		"Instance not found"
//	@Failure		500			{object}	types.ErrorResponse		"Failed to get instance status"
//	@Router			/status [get]
func GetInstanceStatus(c *gin.Context) {
	var req InstanceRequest

	// Get parameters from query string
	req.InstanceID = c.Query("instanceId")
	req.Region = c.Query("region")

	// Validate required parameters
	if req.InstanceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Instance ID is required"})
		return
	}

	// Check if the instance exists in the database
	var dbInstance models.AWSInstance
	if err := database.DB.Where("instance_id = ?", req.InstanceID).First(&dbInstance).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found in database"})
			return
		}
		log.Printf("Error querying AWS instance from database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Use the region from the database if not provided in request
	if req.Region == "" {
		req.Region = dbInstance.Region
	}

	// Validate region
	if req.Region == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Region is required"})
		return
	}

	// Create EC2 client for the specific region
	ec2Client, err := createEC2ClientForRegion(req.Region)
	if err != nil {
		log.Printf("Failed to create EC2 client for region %s: %v", req.Region, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create AWS client: %v", err)})
		return
	}

	log.Printf("About to query AWS for instance %s in region %s", req.InstanceID, req.Region)
	
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{req.InstanceID},
	}

	result, err := ec2Client.DescribeInstances(context.TODO(), input)
	if err != nil {
		log.Printf("Failed to get instance status %s in region %s: %v", req.InstanceID, req.Region, err)
		// Check if error is related to endpoint resolution or credentials
		errMsg := err.Error()
		if strings.Contains(errMsg, "ResolveEndpointV2") ||
			strings.Contains(errMsg, "NoCredentialProviders") ||
			strings.Contains(errMsg, "region") {
			log.Printf("AWS configuration error for instance %s: %v", req.InstanceID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("AWS configuration error: %v", err)})
		} else {
			log.Printf("General AWS API error for instance %s: %v", req.InstanceID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get instance status: %v", err)})
		}
		return
	}
	
	log.Printf("Successfully retrieved instance status for %s, result count: %d", req.InstanceID, len(result.Reservations))

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
		return
	}

	instanceState := result.Reservations[0].Instances[0].State.Name
	// Update only the status in the database
	if err := database.DB.Model(&dbInstance).Update("Status", string(instanceState)).Error; err != nil {
		log.Printf("Failed to update instance status in database: %v", err)
		// Continue anyway, just log the error
	}

	c.JSON(http.StatusOK, gin.H{
		"state":  string(instanceState),
		"name":   req.InstanceID,
		"region": req.Region,
	})
}

// GetInstances godoc
//
//	@Summary		Get list of AWS instances
//	@Description	Get a list of all AWS instances in the database
//	@Tags			VPN Management
//	@Produce		json
//	@Success		200	{array}		models.AWSInstance	"List of AWS instances"
//	@Failure		500	{object}	types.ErrorResponse	"Failed to fetch instances"
//	@Router			/instances [get]
func GetInstances(c *gin.Context) {
	var instances []models.AWSInstance

	// Get user ID from context to filter instances they created
	userIDStr, exists := c.Get("userId")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User information not available"})
		return
	}

	// Convert user ID from string to uint
	userID, err := strconv.ParseUint(userIDStr.(string), 10, 32)
	if err != nil {
		log.Printf("Failed to parse user ID: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID"})
		return
	}

	// Query instances from database - only return instances created by the current user
	if err := database.DB.Where("created_by = ?", uint(userID)).Find(&instances).Error; err != nil {
		log.Printf("Failed to fetch AWS instances: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch instances"})
		return
	}

	c.JSON(http.StatusOK, instances)
}

// GetInstance godoc
//
//	@Summary		Get a specific AWS instance
//	@Description	Get details of a specific AWS instance by ID
//	@Tags			VPN Management
//	@Produce		json
//	@Param			id	path		string				true	"Instance ID"
//	@Success		200	{object}	models.AWSInstance	"AWS instance details"
//	@Failure		404	{object}	types.ErrorResponse	"Instance not found"
//	@Failure		500	{object}	types.ErrorResponse	"Failed to fetch instance"
//	@Router			/instances/{id} [get]
func GetInstance(c *gin.Context) {
	idParam := c.Param("id")
	
	// Convert the ID parameter to uint
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		log.Printf("Failed to parse instance ID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid instance ID"})
		return
	}

	var instance models.AWSInstance
	if err := database.DB.First(&instance, uint(id)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
			return
		}
		log.Printf("Failed to fetch AWS instance: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch instance"})
		return
	}

	c.JSON(http.StatusOK, instance)
}

// CreateInstance godoc
//
//	@Summary		Create a new AWS instance
//	@Description	Create a new AWS instance configuration in the database
//	@Tags			VPN Management
//	@Accept			json
//	@Produce		json
//	@Param			instance	body		models.AWSInstance	true	"AWS Instance"
//	@Success		201			{object}	models.AWSInstance	"Created AWS instance"
//	@Failure		400			{object}	types.ErrorResponse	"Bad request"
//	@Failure		500			{object}	types.ErrorResponse	"Failed to create instance"
//	@Router			/instances [post]
func CreateInstance(c *gin.Context) {
	var req models.AWSInstance
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user ID from context
	userIDStr, exists := c.Get("userId")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User information not available"})
		return
	}

	// Convert user ID from string to uint
	userID, err := strconv.ParseUint(userIDStr.(string), 10, 32)
	if err != nil {
		log.Printf("Failed to parse user ID: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID"})
		return
	}
	req.CreatedBy = uint(userID)

	// Validate required fields
	if req.InstanceID == "" || req.Region == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Instance ID and Region are required"})
		return
	}

	// Check if instance with this ID already exists
	var existingInstance models.AWSInstance
	if err := database.DB.Where("instance_id = ?", req.InstanceID).First(&existingInstance).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Instance with this ID already exists"})
		return
	}

	// Create the instance in the database
	if err := database.DB.Create(&req).Error; err != nil {
		log.Printf("Failed to create AWS instance: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create instance"})
		return
	}

	c.JSON(http.StatusCreated, req)
}

// UpdateInstance godoc
//
//	@Summary		Update an existing AWS instance
//	@Description	Update an existing AWS instance configuration in the database
//	@Tags			VPN Management
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string				true	"Instance ID"
//	@Param			instance	body		models.AWSInstance	true	"AWS Instance"
//	@Success		200			{object}	models.AWSInstance	"Updated AWS instance"
//	@Failure		400			{object}	types.ErrorResponse	"Bad request"
//	@Failure		404			{object}	types.ErrorResponse	"Instance not found"
//	@Failure		500			{object}	types.ErrorResponse	"Failed to update instance"
//	@Router			/instances/{id} [put]
func UpdateInstance(c *gin.Context) {
	idParam := c.Param("id")
	
	// Convert the ID parameter to uint
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		log.Printf("Failed to parse instance ID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid instance ID"})
		return
	}

	var instance models.AWSInstance
	if err := database.DB.First(&instance, uint(id)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
			return
		}
		log.Printf("Failed to fetch AWS instance for update: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch instance"})
		return
	}

	var req models.AWSInstance
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update only allowed fields (avoid updating ID, CreatedBy, timestamps)
	instance.Name = req.Name
	instance.Region = req.Region
	instance.Description = req.Description

	if err := database.DB.Save(&instance).Error; err != nil {
		log.Printf("Failed to update AWS instance: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update instance"})
		return
	}

	c.JSON(http.StatusOK, instance)
}

// DeleteInstance godoc
//
//	@Summary		Delete an AWS instance
//	@Description	Delete an AWS instance configuration from the database
//	@Tags			VPN Management
//	@Produce		json
//	@Param			id	path	string	true	"Instance ID"
//	@Success		204	"Instance deleted successfully"
//	@Failure		404	{object}	types.ErrorResponse	"Instance not found"
//	@Failure		500	{object}	types.ErrorResponse	"Failed to delete instance"
//	@Router			/instances/{id} [delete]
func DeleteInstance(c *gin.Context) {
	idParam := c.Param("id")
	
	// Convert the ID parameter to uint
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		log.Printf("Failed to parse instance ID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid instance ID"})
		return
	}

	var instance models.AWSInstance
	if err := database.DB.First(&instance, uint(id)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
			return
		}
		log.Printf("Failed to fetch AWS instance for deletion: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch instance"})
		return
	}

	// Verify that the current user owns this instance (for non-admin users)
	userIDStr, exists := c.Get("userId")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User information not available"})
		return
	}

	// Convert user ID from string to uint
	userID, err := strconv.ParseUint(userIDStr.(string), 10, 32)
	if err != nil {
		log.Printf("Failed to parse user ID: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID"})
		return
	}

	if instance.CreatedBy != uint(userID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You can only delete your own instances"})
		return
	}

	if err := database.DB.Delete(&instance).Error; err != nil {
		log.Printf("Failed to delete AWS instance: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete instance"})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// AdminCreateInstance godoc
//
//	@Summary		Admin: Create a new AWS instance
//	@Description	Create a new AWS instance configuration in the database (admin only)
//	@Tags			VPN Management
//	@Accept			json
//	@Produce		json
//	@Param			instance	body		models.AWSInstance	true	"AWS Instance"
//	@Success		201			{object}	models.AWSInstance	"Created AWS instance"
//	@Failure		400			{object}	types.ErrorResponse	"Bad request"
//	@Failure		500			{object}	types.ErrorResponse	"Failed to create instance"
//	@Router			/admin/instances [post]
func AdminCreateInstance(c *gin.Context) {
	var req models.AWSInstance
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate required fields
	if req.InstanceID == "" || req.Region == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Instance ID and Region are required"})
		return
	}

	// Check if instance with this ID already exists
	var existingInstance models.AWSInstance
	if err := database.DB.Where("instance_id = ?", req.InstanceID).First(&existingInstance).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Instance with this ID already exists"})
		return
	}

	// Admin can create instance for any user, default to admin's user ID if not specified
	if req.CreatedBy == 0 {
		adminUserIDStr, exists := c.Get("userId")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User information not available"})
			return
		}
		
		// Convert user ID from string to uint
		adminUserID, err := strconv.ParseUint(adminUserIDStr.(string), 10, 32)
		if err != nil {
			log.Printf("Failed to parse user ID: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID"})
			return
		}
		req.CreatedBy = uint(adminUserID)
	}

	// Create the instance in the database
	if err := database.DB.Create(&req).Error; err != nil {
		log.Printf("Failed to create AWS instance: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create instance"})
		return
	}

	c.JSON(http.StatusCreated, req)
}

// AdminUpdateInstance godoc
//
//	@Summary		Admin: Update an existing AWS instance
//	@Description	Update an existing AWS instance configuration in the database (admin only)
//	@Tags			VPN Management
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string				true	"Instance ID"
//	@Param			instance	body		models.AWSInstance	true	"AWS Instance"
//	@Success		200			{object}	models.AWSInstance	"Updated AWS instance"
//	@Failure		400			{object}	types.ErrorResponse	"Bad request"
//	@Failure		404			{object}	types.ErrorResponse	"Instance not found"
//	@Failure		500			{object}	types.ErrorResponse	"Failed to update instance"
//	@Router			/admin/instances/{id} [put]
func AdminUpdateInstance(c *gin.Context) {
	idParam := c.Param("id")
	
	// Convert the ID parameter to uint
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		log.Printf("Failed to parse instance ID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid instance ID"})
		return
	}

	var instance models.AWSInstance
	if err := database.DB.First(&instance, uint(id)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
			return
		}
		log.Printf("Failed to fetch AWS instance for update: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch instance"})
		return
	}

	var req models.AWSInstance
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update allowed fields
	instance.Name = req.Name
	instance.Region = req.Region
	instance.Description = req.Description
	// Note: Not allowing update of InstanceID or CreatedBy as these are critical fields

	if err := database.DB.Save(&instance).Error; err != nil {
		log.Printf("Failed to update AWS instance: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update instance"})
		return
	}

	c.JSON(http.StatusOK, instance)
}

// AdminDeleteInstance godoc
//
//	@Summary		Admin: Delete an AWS instance
//	@Description	Delete an AWS instance configuration from the database (admin only)
//	@Tags			VPN Management
//	@Produce		json
//	@Param			id	path	string	true	"Instance ID"
//	@Success		204	"Instance deleted successfully"
//	@Failure		404	{object}	types.ErrorResponse	"Instance not found"
//	@Failure		500	{object}	types.ErrorResponse	"Failed to delete instance"
//	@Router			/admin/instances/{id} [delete]
func AdminDeleteInstance(c *gin.Context) {
	idParam := c.Param("id")
	
	// Convert the ID parameter to uint
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		log.Printf("Failed to parse instance ID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid instance ID"})
		return
	}

	var instance models.AWSInstance
	if err := database.DB.First(&instance, uint(id)).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
			return
		}
		log.Printf("Failed to fetch AWS instance for deletion: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch instance"})
		return
	}

	// Admins can delete any instance
	if err := database.DB.Delete(&instance).Error; err != nil {
		log.Printf("Failed to delete AWS instance: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete instance"})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}
