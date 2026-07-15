// SPDX-License-Identifier: AGPL-3.0-or-later

// Package managedapps controls real Amazon Elastic Container Service workloads
// registered in Shauth's application catalog.
package managedapps

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/e6qu/shauth/internal/identity"
)

type ServiceStatus struct {
	DesiredCount int32
	RunningCount int32
	PendingCount int32
}

type LogEvent struct {
	Timestamp time.Time
	Stream    string
	Message   string
}

type Controller struct {
	cluster string
	ecs     *ecs.Client
	logs    *cloudwatchlogs.Client
}

func New(ctx context.Context, region, cluster string) (*Controller, error) {
	if region == "" || cluster == "" {
		return nil, fmt.Errorf("Amazon Elastic Container Service region and cluster are required")
	}
	configuration, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load Amazon Web Services configuration: %w", err)
	}
	return &Controller{cluster: cluster, ecs: ecs.NewFromConfig(configuration), logs: cloudwatchlogs.NewFromConfig(configuration)}, nil
}

func (controller *Controller) Status(ctx context.Context, app identity.ManagedApp) (ServiceStatus, error) {
	response, err := controller.ecs.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: aws.String(controller.cluster), Services: []string{app.ECSServiceName}})
	if err != nil {
		return ServiceStatus{}, fmt.Errorf("describe Amazon Elastic Container Service service %q: %w", app.ECSServiceName, err)
	}
	if len(response.Services) != 1 {
		return ServiceStatus{}, fmt.Errorf("Amazon Elastic Container Service service %q was not found", app.ECSServiceName)
	}
	service := response.Services[0]
	return ServiceStatus{DesiredCount: service.DesiredCount, RunningCount: service.RunningCount, PendingCount: service.PendingCount}, nil
}

func (controller *Controller) Start(ctx context.Context, app identity.ManagedApp) error {
	_, err := controller.ecs.UpdateService(ctx, &ecs.UpdateServiceInput{Cluster: aws.String(controller.cluster), Service: aws.String(app.ECSServiceName), DesiredCount: aws.Int32(1)})
	if err != nil {
		return fmt.Errorf("start Amazon Elastic Container Service service %q: %w", app.ECSServiceName, err)
	}
	return nil
}

func (controller *Controller) Stop(ctx context.Context, app identity.ManagedApp) error {
	_, err := controller.ecs.UpdateService(ctx, &ecs.UpdateServiceInput{Cluster: aws.String(controller.cluster), Service: aws.String(app.ECSServiceName), DesiredCount: aws.Int32(0)})
	if err != nil {
		return fmt.Errorf("stop Amazon Elastic Container Service service %q: %w", app.ECSServiceName, err)
	}
	return nil
}

func (controller *Controller) Logs(ctx context.Context, app identity.ManagedApp) ([]LogEvent, error) {
	response, err := controller.logs.FilterLogEvents(ctx, &cloudwatchlogs.FilterLogEventsInput{LogGroupName: aws.String(app.CloudWatchLogGroup), StartTime: aws.Int64(time.Now().Add(-15 * time.Minute).UnixMilli()), Limit: aws.Int32(100), Interleaved: aws.Bool(true)})
	if err != nil {
		return nil, fmt.Errorf("read Amazon CloudWatch Logs group %q: %w", app.CloudWatchLogGroup, err)
	}
	events := make([]LogEvent, 0, len(response.Events))
	for _, event := range response.Events {
		if event.Timestamp == nil || event.Message == nil {
			continue
		}
		events = append(events, LogEvent{Timestamp: time.UnixMilli(*event.Timestamp).UTC(), Stream: aws.ToString(event.LogStreamName), Message: *event.Message})
	}
	return events, nil
}
