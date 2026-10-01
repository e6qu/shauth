// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mailer sends Shauth invitations through Amazon Simple Email Service.
package mailer

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

type Invitations interface {
	SendInvitation(context.Context, string, string) error
	// SendingReady reports whether the configured sender can currently
	// send, as Amazon SES itself reports it.
	SendingReady(context.Context) error
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
	_, err := s.client.SendEmail(ctx, &sesv2.SendEmailInput{FromEmailAddress: aws.String(s.from), Destination: &types.Destination{ToAddresses: []string{email}}, Content: &types.EmailContent{Simple: &types.Message{Subject: &types.Content{Data: aws.String("You have been invited to Shauth")}, Body: &types.Body{Text: &types.Content{Data: aws.String("Accept your invitation and set a password: " + link)}}}}})
	if err != nil {
		return fmt.Errorf("send Amazon Simple Email Service invitation: %w", err)
	}
	return nil
}

// SendingReady asks Amazon SES whether the sender's identity, its domain, is
// verified for sending.
func (s *SES) SendingReady(ctx context.Context) error {
	identity := s.from
	if at := strings.LastIndex(identity, "@"); at >= 0 {
		identity = identity[at+1:]
	}
	output, err := s.client.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{EmailIdentity: aws.String(identity)})
	if err != nil {
		return fmt.Errorf("read Amazon Simple Email Service identity %s: %w", identity, err)
	}
	if !output.VerifiedForSendingStatus {
		return fmt.Errorf("Amazon Simple Email Service identity %s is not verified for sending (status %s)", identity, output.VerificationStatus)
	}
	return nil
}
