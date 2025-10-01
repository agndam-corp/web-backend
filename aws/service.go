package aws

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// EC2Service defines an interface for EC2 operations to enable easier testing
type EC2Service interface {
	StartInstance(ctx context.Context, instanceID, region string) error
	StopInstance(ctx context.Context, instanceID, region string) error
	GetInstanceStatus(ctx context.Context, instanceID, region string) (string, error)
}

// DefaultEC2Service implements EC2Service using the AWS SDK
type DefaultEC2Service struct{}

// NewDefaultEC2Service creates a new instance of DefaultEC2Service
func NewDefaultEC2Service() *DefaultEC2Service {
	return &DefaultEC2Service{}
}

// StartInstance starts an EC2 instance
func (s *DefaultEC2Service) StartInstance(ctx context.Context, instanceID, region string) error {
	// Create a config with the specific region
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(defaultProfile),
		config.WithRegion(region),
	)
	if err != nil {
		log.Printf("Failed to load AWS config for region %s: %v", region, err)
		return err
	}

	ec2Client := ec2.NewFromConfig(cfg)

	input := &ec2.StartInstancesInput{
		InstanceIds: []string{instanceID},
	}

	_, err = ec2Client.StartInstances(ctx, input)
	if err != nil {
		log.Printf("Failed to start instance %s in region %s: %v", instanceID, region, err)
		return err
	}

	log.Printf("Successfully sent start command for instance %s", instanceID)
	return nil
}

// StopInstance stops an EC2 instance
func (s *DefaultEC2Service) StopInstance(ctx context.Context, instanceID, region string) error {
	// Create a config with the specific region
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(defaultProfile),
		config.WithRegion(region),
	)
	if err != nil {
		log.Printf("Failed to load AWS config for region %s: %v", region, err)
		return err
	}

	ec2Client := ec2.NewFromConfig(cfg)

	input := &ec2.StopInstancesInput{
		InstanceIds: []string{instanceID},
	}

	_, err = ec2Client.StopInstances(ctx, input)
	if err != nil {
		log.Printf("Failed to stop instance %s in region %s: %v", instanceID, region, err)
		return err
	}

	log.Printf("Successfully sent stop command for instance %s", instanceID)
	return nil
}

// GetInstanceStatus gets the status of an EC2 instance
func (s *DefaultEC2Service) GetInstanceStatus(ctx context.Context, instanceID, region string) (string, error) {
	// Create a config with the specific region
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(defaultProfile),
		config.WithRegion(region),
	)
	if err != nil {
		log.Printf("Failed to load AWS config for region %s: %v", region, err)
		return "", err
	}

	ec2Client := ec2.NewFromConfig(cfg)

	input := &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	}

	result, err := ec2Client.DescribeInstances(ctx, input)
	if err != nil {
		log.Printf("Failed to get instance status %s in region %s: %v", instanceID, region, err)
		return "", err
	}

	if len(result.Reservations) == 0 || len(result.Reservations[0].Instances) == 0 {
		return "", nil // Instance not found
	}

	state := string(result.Reservations[0].Instances[0].State.Name)
	return state, nil
}