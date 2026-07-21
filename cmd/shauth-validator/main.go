// SPDX-License-Identifier: AGPL-3.0-or-later

// Shauth-validator runs real browser acceptance checks claimed from Shauth.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

var oauthQueryValue = regexp.MustCompile(`(?i)([?&](?:code|state|token|challenge|consent_challenge|login_challenge|logout_challenge|login_verifier|consent_verifier|logout_verifier|id_token_hint|logout_hint|access_token|refresh_token|device_code)=)[^&\s]+`)
var immutableReleaseRevision = regexp.MustCompile(`^([0-9a-f]{12,64}|sha256:[0-9a-f]{64})$`)
var browserBootstrapTokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type job struct {
	ID              string   `json:"id"`
	ManagedAppID    string   `json:"managed_app_id"`
	AppSlug         string   `json:"app_slug"`
	AppName         string   `json:"app_name"`
	OIDCClientID    string   `json:"oidc_client_id"`
	LaunchURL       string   `json:"launch_url"`
	ValidationURL   string   `json:"validation_url"`
	SignedOutURL    string   `json:"signed_out_url"`
	LogoutBridgeURL string   `json:"logout_bridge_url"`
	Direction       string   `json:"direction"`
	ReleaseRevision string   `json:"release_revision"`
	ShauthURL       string   `json:"shauth_url"`
	BootstrapURLs   []string `json:"bootstrap_urls"`
	Witness         *witness `json:"witness"`
}

type witness struct {
	ManagedAppID    string `json:"managed_app_id"`
	AppSlug         string `json:"app_slug"`
	AppName         string `json:"app_name"`
	OIDCClientID    string `json:"oidc_client_id"`
	LaunchURL       string `json:"launch_url"`
	ValidationURL   string `json:"validation_url"`
	SignedOutURL    string `json:"signed_out_url"`
	LogoutBridgeURL string `json:"logout_bridge_url"`
	ReleaseRevision string `json:"release_revision"`
}

type result struct {
	Status  string `json:"status"`
	Failure string `json:"failure"`
}

type bootstrapResponse struct {
	URLs []string `json:"urls"`
}

func main() {
	baseURL := required("SHAUTH_URL")
	token := required("SHAUTH_VALIDATOR_TOKEN")
	_ = required("SHAUTH_VALIDATION_USERNAME")
	_ = required("SHAUTH_VALIDATION_EMAIL")
	script := required("SHAUTH_VALIDATOR_SCRIPT")
	client := &http.Client{Timeout: 30 * time.Second}
	consecutiveClaimFailures := 0
	for {
		claimed, err := claim(context.Background(), client, baseURL, token)
		if err != nil {
			consecutiveClaimFailures++
			log.Printf("claim validation: %v", err)
			if consecutiveClaimFailures >= 12 {
				log.Fatalf("Shauth validation queue remained unavailable after %d attempts", consecutiveClaimFailures)
			}
			time.Sleep(5 * time.Second)
			continue
		}
		consecutiveClaimFailures = 0
		if claimed == nil {
			time.Sleep(5 * time.Second)
			continue
		}
		if err := validateJob(baseURL, *claimed); err != nil {
			if completeErr := complete(context.Background(), client, baseURL, token, claimed.ID, result{Status: "failed", Failure: err.Error()}); completeErr != nil {
				log.Printf("reject invalid validation %s: %v; record failure: %v", claimed.ID, err, completeErr)
			}
			continue
		}
		nextPaths := []string{"/", "/", "/"}
		if claimed.Direction == "from_shauth" {
			nextPaths[0] = "/apps"
		}
		bootstrapURLs, err := createBrowserBootstraps(context.Background(), client, baseURL, token, nextPaths)
		if err != nil {
			outcome := result{Status: "failed", Failure: sanitizeFailure("create validation browser sessions: " + err.Error())}
			if completeErr := complete(context.Background(), client, baseURL, token, claimed.ID, outcome); completeErr != nil {
				log.Printf("record browser bootstrap failure for validation %s: %v", claimed.ID, completeErr)
			}
			continue
		}
		if err := validateBootstrapURLs(baseURL, bootstrapURLs); err != nil {
			outcome := result{Status: "failed", Failure: err.Error()}
			if completeErr := complete(context.Background(), client, baseURL, token, claimed.ID, outcome); completeErr != nil {
				log.Printf("record invalid browser bootstrap response for validation %s: %v", claimed.ID, completeErr)
			}
			continue
		}
		claimed.BootstrapURLs = bootstrapURLs
		outcome := run(context.Background(), script, *claimed)
		if err := complete(context.Background(), client, baseURL, token, claimed.ID, outcome); err != nil {
			log.Printf("complete validation %s: %v", claimed.ID, err)
		}
	}
}

func createBrowserBootstraps(ctx context.Context, client *http.Client, baseURL, token string, nextPaths []string) ([]string, error) {
	payload, err := json.Marshal(map[string]any{"next": nextPaths})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/internal/validator/browser-bootstraps", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("browser bootstrap returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	var issued bootstrapResponse
	if err := decodeSingleJSON(io.LimitReader(response.Body, 16*1024), &issued); err != nil {
		return nil, fmt.Errorf("decode browser bootstrap: %w", err)
	}
	return issued.URLs, nil
}

func required(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("%s must be set", name)
	}
	return value
}

func claim(ctx context.Context, client *http.Client, baseURL, token string) (*job, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/internal/validator/jobs/claim", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("claim returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	var claimed job
	if err := decodeSingleJSON(io.LimitReader(response.Body, 64*1024), &claimed); err != nil {
		return nil, fmt.Errorf("decode claim: %w", err)
	}
	return &claimed, nil
}

func decodeSingleJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func run(ctx context.Context, script string, claimed job) result {
	payload, err := json.Marshal(claimed)
	if err != nil {
		return result{Status: "failed", Failure: "encode browser job: " + err.Error()}
	}
	runContext, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	command := exec.CommandContext(runContext, "node", script)
	command.Stdin = bytes.NewReader(payload)
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"NODE_PATH=" + os.Getenv("NODE_PATH"),
		"PLAYWRIGHT_BROWSERS_PATH=" + os.Getenv("PLAYWRIGHT_BROWSERS_PATH"),
		"SHAUTH_VALIDATION_USERNAME=" + os.Getenv("SHAUTH_VALIDATION_USERNAME"),
		"SHAUTH_VALIDATION_EMAIL=" + os.Getenv("SHAUTH_VALIDATION_EMAIL"),
	}
	output, err := command.CombinedOutput()
	if err != nil {
		failure := sanitizeJobFailure(string(output), claimed)
		if failure == "" {
			failure = sanitizeJobFailure(err.Error(), claimed)
		}
		return result{Status: "failed", Failure: failure}
	}
	var outcome result
	if err := decodeSingleJSON(bytes.NewReader(output), &outcome); err != nil {
		return result{Status: "failed", Failure: sanitizeJobFailure("decode browser result: "+err.Error()+": "+string(output), claimed)}
	}
	if outcome.Status != "passed" && outcome.Status != "failed" {
		return result{Status: "failed", Failure: "browser returned an invalid status"}
	}
	outcome.Failure = sanitizeJobFailure(outcome.Failure, claimed)
	return outcome
}

func sanitizeFailure(value string) string {
	username := os.Getenv("SHAUTH_VALIDATION_USERNAME")
	secrets := []string{
		username,
		os.Getenv("SHAUTH_VALIDATOR_TOKEN"),
	}
	value = redactCredentialMaterial(value, secrets)
	value = oauthQueryValue.ReplaceAllString(value, "$1[redacted]")
	value = strings.TrimSpace(value)
	if len(value) > 1000 {
		value = value[:1000]
	}
	return value
}

func sanitizeJobFailure(value string, claimed job) string {
	secrets := make([]string, 0, len(claimed.BootstrapURLs))
	for _, rawURL := range claimed.BootstrapURLs {
		coordinate, err := url.Parse(rawURL)
		if err == nil && coordinate.Fragment != "" {
			secrets = append(secrets, coordinate.Fragment)
		}
	}
	value = redactCredentialMaterial(value, secrets)
	return sanitizeFailure(value)
}

func redactCredentialMaterial(value string, secrets []string) string {
	variants := make(map[string]struct{})
	for _, secret := range secrets {
		for _, candidate := range encodedSecretVariants(secret) {
			variants[candidate] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(variants))
	for candidate := range variants {
		ordered = append(ordered, candidate)
	}
	slices.SortFunc(ordered, func(left, right string) int {
		return len(right) - len(left)
	})
	for _, candidate := range ordered {
		value = strings.ReplaceAll(value, candidate, "[redacted]")
	}
	return value
}

func encodedSecretVariants(secret string) []string {
	if secret == "" {
		return nil
	}
	seen := make(map[string]struct{})
	frontier := []string{secret}
	for depth := 0; depth <= 4 && len(frontier) > 0; depth++ {
		next := make([]string, 0, len(frontier)*6)
		for _, value := range frontier {
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			encoded := []string{
				url.QueryEscape(value),
				url.PathEscape(value),
				base64.StdEncoding.EncodeToString([]byte(value)),
				base64.RawStdEncoding.EncodeToString([]byte(value)),
				base64.URLEncoding.EncodeToString([]byte(value)),
				base64.RawURLEncoding.EncodeToString([]byte(value)),
			}
			for _, candidate := range encoded {
				if candidate != "" {
					if _, exists := seen[candidate]; !exists {
						next = append(next, candidate)
					}
				}
			}
		}
		frontier = next
	}
	result := make([]string, 0, len(seen))
	for candidate := range seen {
		result = append(result, candidate)
	}
	return result
}

func validateJob(baseURL string, claimed job) error {
	provider, err := url.Parse(baseURL)
	if err != nil || !validServiceURL(provider) || (provider.Path != "" && provider.Path != "/") || provider.RawQuery != "" {
		return fmt.Errorf("configured Shauth URL is invalid")
	}
	claimedProvider, err := url.Parse(claimed.ShauthURL)
	if err != nil || !validServiceURL(claimedProvider) || (claimedProvider.Path != "" && claimedProvider.Path != "/") || claimedProvider.RawQuery != "" || provider.Scheme != claimedProvider.Scheme || !strings.EqualFold(provider.Host, claimedProvider.Host) {
		return fmt.Errorf("job Shauth origin does not match the configured Shauth origin")
	}
	appOrigin, err := validateApplicationCoordinates("application", claimed.LaunchURL, claimed.ValidationURL, claimed.SignedOutURL, claimed.LogoutBridgeURL)
	if err != nil {
		return err
	}
	if strings.TrimSpace(claimed.ManagedAppID) == "" || strings.TrimSpace(claimed.OIDCClientID) == "" {
		return fmt.Errorf("job application identity is invalid")
	}
	if !immutableReleaseRevision.MatchString(claimed.ReleaseRevision) {
		return fmt.Errorf("job application release revision is not immutable")
	}
	if claimed.Witness == nil {
		return fmt.Errorf("global SSO logout requires a second managed app with a distinct OpenID Connect client and origin")
	}
	witnessOrigin, err := validateApplicationCoordinates("witness", claimed.Witness.LaunchURL, claimed.Witness.ValidationURL, claimed.Witness.SignedOutURL, claimed.Witness.LogoutBridgeURL)
	if err != nil {
		return err
	}
	if strings.TrimSpace(claimed.Witness.ManagedAppID) == "" || claimed.Witness.ManagedAppID == claimed.ManagedAppID || strings.TrimSpace(claimed.Witness.OIDCClientID) == "" || claimed.Witness.OIDCClientID == claimed.OIDCClientID {
		return fmt.Errorf("job logout witness identity is invalid")
	}
	if !immutableReleaseRevision.MatchString(claimed.Witness.ReleaseRevision) {
		return fmt.Errorf("job witness release revision is not immutable")
	}
	if appOrigin.Scheme == witnessOrigin.Scheme && strings.EqualFold(appOrigin.Host, witnessOrigin.Host) {
		return fmt.Errorf("job logout witness must use a distinct origin")
	}
	if claimed.Direction != "from_shauth" && claimed.Direction != "from_app" {
		return fmt.Errorf("job validation direction is invalid")
	}
	return nil
}

func validateBootstrapURLs(baseURL string, bootstrapURLs []string) error {
	if len(bootstrapURLs) != 3 {
		return fmt.Errorf("Shauth returned an invalid number of browser bootstraps")
	}
	provider, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("configured Shauth URL is invalid")
	}
	seen := make(map[string]struct{}, len(bootstrapURLs))
	for _, rawURL := range bootstrapURLs {
		coordinate, err := url.Parse(rawURL)
		if err != nil || coordinate.Scheme != provider.Scheme || !strings.EqualFold(coordinate.Host, provider.Host) || coordinate.Path != "/validator/bootstrap" || coordinate.RawQuery != "" || coordinate.User != nil || !browserBootstrapTokenPattern.MatchString(coordinate.Fragment) {
			return fmt.Errorf("Shauth returned an invalid browser bootstrap coordinate")
		}
		if _, duplicate := seen[coordinate.Fragment]; duplicate {
			return fmt.Errorf("Shauth returned duplicate browser bootstraps")
		}
		seen[coordinate.Fragment] = struct{}{}
	}
	return nil
}

func validateApplicationCoordinates(label, launch, validation, signedOut, logoutBridge string) (*url.URL, error) {
	var origin *url.URL
	for coordinateLabel, raw := range map[string]string{"launch": launch, "validation": validation, "signed-out": signedOut, "logout bridge": logoutBridge} {
		coordinate, err := url.Parse(raw)
		if err != nil || !validServiceURL(coordinate) {
			return nil, fmt.Errorf("job %s %s URL is invalid", label, coordinateLabel)
		}
		if origin == nil {
			origin = coordinate
			continue
		}
		if coordinate.Scheme != origin.Scheme || !strings.EqualFold(coordinate.Host, origin.Host) {
			return nil, fmt.Errorf("job %s URLs do not share one origin", label)
		}
	}
	expectedLogoutBridge := origin.Scheme + "://" + origin.Host + "/auth/shauth/logout/complete"
	if logoutBridge != expectedLogoutBridge {
		return nil, fmt.Errorf("job %s logout bridge URL must be %s", label, expectedLogoutBridge)
	}
	return origin, nil
}

func validServiceURL(value *url.URL) bool {
	if value == nil || value.Host == "" || value.User != nil || value.Fragment != "" {
		return false
	}
	if value.Scheme == "https" {
		return true
	}
	host := strings.Trim(strings.ToLower(value.Hostname()), "[]")
	return value.Scheme == "http" && (host == "localhost" || strings.HasSuffix(host, ".localhost") || net.ParseIP(host).IsLoopback())
}

func complete(ctx context.Context, client *http.Client, baseURL, token, runID string, outcome result) error {
	payload, err := json.Marshal(outcome)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/internal/validator/jobs/"+runID+"/complete", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("complete returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
