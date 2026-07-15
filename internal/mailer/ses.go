// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mailer sends Shauth invitations through Amazon Simple Email Service.
package mailer

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

type Invitations interface {
	SendInvitation(context.Context, string, string) error
}
type SES struct {
	client *sesv2.Client
	from   string
}

func NewSES(ctx context.Context, region, from string) (*SES, error) {
	if region == "" || from == "" {
		return nil, fmt.Errorf("Amazon Simple Email Service region and sender are required")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	return &SES{client: sesv2.NewFromConfig(cfg), from: from}, nil
}
func (s *SES) SendInvitation(ctx context.Context, email, link string) error {
	_, err := s.client.SendEmail(ctx, &sesv2.SendEmailInput{FromEmailAddress: aws.String(s.from), Destination: &types.Destination{ToAddresses: []string{email}}, Content: &types.EmailContent{Simple: &types.Message{Subject: &types.Content{Data: aws.String("You have been invited to e6qu")}, Body: &types.Body{Text: &types.Content{Data: aws.String("Accept your invitation and set a password: " + link)}}}}})
	if err != nil {
		return fmt.Errorf("send Amazon Simple Email Service invitation: %w", err)
	}
	return nil
}
