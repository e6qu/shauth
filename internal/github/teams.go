// SPDX-License-Identifier: AGPL-3.0-or-later

// Package github evaluates GitHub organization-team membership for Shauth roles.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const teamsEndpoint = "https://api.github.com/user/teams"
const userEndpoint = "https://api.github.com/user"
const emailsEndpoint = "https://api.github.com/user/emails"
const organizationsEndpoint = "https://api.github.com/user/memberships/orgs"

type Profile struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Email string `json:"email"`
}

type Team struct {
	Slug         string `json:"slug"`
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
}
type OrganizationMembership struct {
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
}

// Profile retrieves the authenticated GitHub user's stable identifier and
// verified public email address. GitHub OAuth must request the user:email scope
// if an account has made its email private.
func (client *Client) Profile(ctx context.Context, accessToken string) (Profile, error) {
	if strings.TrimSpace(accessToken) == "" {
		return Profile{}, fmt.Errorf("GitHub access token must not be empty")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, userEndpoint, nil)
	if err != nil {
		return Profile{}, fmt.Errorf("build GitHub user request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return Profile{}, fmt.Errorf("request GitHub user: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Profile{}, fmt.Errorf("GitHub user returned HTTP %d", response.StatusCode)
	}
	var profile Profile
	if err := json.NewDecoder(response.Body).Decode(&profile); err != nil {
		return Profile{}, fmt.Errorf("decode GitHub user: %w", err)
	}
	email, err := client.primaryVerifiedEmail(ctx, accessToken)
	if err != nil {
		return Profile{}, err
	}
	profile.Email = email
	if profile.ID == 0 || strings.TrimSpace(profile.Login) == "" || strings.TrimSpace(profile.Email) == "" {
		return Profile{}, fmt.Errorf("GitHub user response lacks id, login, or verified email")
	}
	return profile, nil
}

func (client *Client) primaryVerifiedEmail(ctx context.Context, accessToken string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, emailsEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build GitHub email request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("request GitHub emails: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub emails returned HTTP %d", response.StatusCode)
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(response.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("decode GitHub emails: %w", err)
	}
	for _, email := range emails {
		if email.Primary && email.Verified && strings.TrimSpace(email.Email) != "" {
			return email.Email, nil
		}
	}
	return "", fmt.Errorf("GitHub account has no primary verified email")
}

type Client struct {
	httpClient *http.Client
	endpoint   *url.URL
}

func NewClient(httpClient *http.Client) (*Client, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("GitHub client requires an HTTP client")
	}
	endpoint, err := url.Parse(teamsEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parse GitHub teams endpoint: %w", err)
	}
	return &Client{httpClient: httpClient, endpoint: endpoint}, nil
}

// IsMember reports whether the token's GitHub user belongs to organization/slug.
func (client *Client) IsMember(ctx context.Context, accessToken, organization, slug string) (bool, error) {
	teams, err := client.Teams(ctx, accessToken)
	if err != nil {
		return false, err
	}
	for _, team := range teams {
		if strings.EqualFold(team.Organization.Login, organization) && strings.EqualFold(team.Slug, slug) {
			return true, nil
		}
	}
	return false, nil
}

// Teams retrieves every team visible to the authenticated GitHub user.
func (client *Client) Teams(ctx context.Context, accessToken string) ([]Team, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("GitHub access token must not be empty")
	}
	var result []Team
	for page := 1; ; page++ {
		endpoint := *client.endpoint
		query := endpoint.Query()
		query.Set("per_page", "100")
		query.Set("page", fmt.Sprint(page))
		endpoint.RawQuery = query.Encode()

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("build GitHub teams request: %w", err)
		}
		request.Header.Set("Accept", "application/vnd.github+json")
		request.Header.Set("Authorization", "Bearer "+accessToken)

		response, err := client.httpClient.Do(request)
		if err != nil {
			return nil, fmt.Errorf("request GitHub teams: %w", err)
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return nil, fmt.Errorf("GitHub teams returned HTTP %d", response.StatusCode)
		}
		var teams []Team
		decodeErr := json.NewDecoder(response.Body).Decode(&teams)
		_ = response.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("decode GitHub teams: %w", decodeErr)
		}
		result = append(result, teams...)
		if len(teams) < 100 {
			return result, nil
		}
	}
}

// Organizations retrieves every organization in which the authenticated GitHub
// user has a membership visible to the OAuth token.
func (client *Client) Organizations(ctx context.Context, accessToken string) ([]string, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("GitHub access token must not be empty")
	}
	endpoint, err := url.Parse(organizationsEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parse GitHub organizations endpoint: %w", err)
	}
	var result []string
	for page := 1; ; page++ {
		requestURL := *endpoint
		query := requestURL.Query()
		query.Set("per_page", "100")
		query.Set("page", fmt.Sprint(page))
		requestURL.RawQuery = query.Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("build GitHub organizations request: %w", err)
		}
		request.Header.Set("Accept", "application/vnd.github+json")
		request.Header.Set("Authorization", "Bearer "+accessToken)
		response, err := client.httpClient.Do(request)
		if err != nil {
			return nil, fmt.Errorf("request GitHub organizations: %w", err)
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return nil, fmt.Errorf("GitHub organizations returned HTTP %d", response.StatusCode)
		}
		var memberships []OrganizationMembership
		decodeErr := json.NewDecoder(response.Body).Decode(&memberships)
		_ = response.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("decode GitHub organizations: %w", decodeErr)
		}
		for _, membership := range memberships {
			if login := strings.TrimSpace(membership.Organization.Login); login != "" {
				result = append(result, login)
			}
		}
		if len(memberships) < 100 {
			return result, nil
		}
	}
}

func ParseTeam(value string) (organization, slug string, err error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("GitHub team must be organization/slug")
	}
	return parts[0], parts[1], nil
}
