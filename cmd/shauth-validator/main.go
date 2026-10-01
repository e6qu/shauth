// SPDX-License-Identifier: AGPL-3.0-or-later

// Shauth-validator runs real browser acceptance checks claimed from Shauth.
package main

import (
	"github.com/e6qu/shauth/internal/observe"
	"unicode/utf8"

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
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

var oauthQueryValue = regexp.MustCompile(`(?i)([?&](?:code|state|token|challenge|consent_challenge|login_challenge|logout_challenge|login_verifier|consent_verifier|logout_verifier|id_token_hint|logout_hint|access_token|refresh_token|device_code)=)[^&\s]+`)
var immutableReleaseRevision = regexp.MustCompile(`^([0-9a-f]{12,64}|sha256:[0-9a-f]{64})$`)
var browserBootstrapTokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type job struct {
	ID                 string   `json:"id"`
	ManagedAppID       string   `json:"managed_app_id"`
	AppSlug            string   `json:"app_slug"`
	AppName            string   `json:"app_name"`
	OIDCClientID       string   `json:"oidc_client_id"`
	LaunchURL          string   `json:"launch_url"`
	ValidationURL      string   `json:"validation_url"`
	SignedOutURL       string   `json:"signed_out_url"`
	LogoutBridgeURL    string   `json:"logout_bridge_url"`
	Direction          string   `json:"direction"`
	ReleaseRevision    string   `json:"release_revision"`
	ShauthURL          string   `json:"shauth_url"`
	BootstrapURLs      []string `json:"bootstrap_urls"`
	Witness            *witness `json:"witness"`
	ValidationUsername string   `json:"validation_username"`
	ValidationEmail    string   `json:"validation_email"`
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
	script := required("SHAUTH_VALIDATOR_SCRIPT")
	client := &http.Client{Timeout: 30 * time.Second}
	// A stop request (a redeploy, or the acceptance stack's TERM) ends the
	// browser run and still records its outcome, instead of leaving the run
	// "running" until its lease expires.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	consecutiveClaimFailures := 0
	for ctx.Err() == nil {
		claimed, err := claim(ctx, client, baseURL, token)
		if err != nil {
			consecutiveClaimFailures++
			observe.Errorf("claim validation: %v", err)
			if consecutiveClaimFailures >= 12 {
				log.Fatalf("Shauth validation queue remained unavailable after %d attempts", consecutiveClaimFailures)
			}
			sleepUnlessStopped(ctx, 5*time.Second)
			continue
		}
		consecutiveClaimFailures = 0
		if claimed == nil {
			sleepUnlessStopped(ctx, 5*time.Second)
			continue
		}
		if err := validateJob(baseURL, *claimed); err != nil {
			if completeErr := complete(context.Background(), client, baseURL, token, claimed.ID, result{Status: "failed", Failure: err.Error()}); completeErr != nil {
				observe.Errorf("reject invalid validation %s: %v; record failure: %v", claimed.ID, err, completeErr)
			}
			continue
		}
		nextPaths := []string{"/", "/", "/"}
		if claimed.Direction == "from_shauth" {
			nextPaths[0] = "/apps"
		}
		bootstrapURLs, err := createBrowserBootstraps(context.Background(), client, baseURL, token, claimed.ID, nextPaths)
		if err != nil {
			outcome := result{Status: "failed", Failure: sanitizeFailure("create validation browser sessions: "+err.Error(), claimed.ValidationUsername)}
			if completeErr := complete(context.Background(), client, baseURL, token, claimed.ID, outcome); completeErr != nil {
				observe.Errorf("record browser bootstrap failure for validation %s: %v", claimed.ID, completeErr)
			}
			continue
		}
		if err := validateBootstrapURLs(baseURL, bootstrapURLs); err != nil {
			outcome := result{Status: "failed", Failure: err.Error()}
			if completeErr := complete(context.Background(), client, baseURL, token, claimed.ID, outcome); completeErr != nil {
				observe.Errorf("record invalid browser bootstrap response for validation %s: %v", claimed.ID, completeErr)
			}
			continue
		}
		claimed.BootstrapURLs = bootstrapURLs
		outcome := run(ctx, script, *claimed)
		if ctx.Err() != nil && outcome.Status != "passed" {
			outcome.Failure = sanitizeJobFailure("the validator was stopped during this run: "+outcome.Failure, *claimed)
		}
		// The outcome is recorded even while stopping, with its own short
		// deadline, and a transient failure to report it is retried.
		reportContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := completeWithRetry(reportContext, client, baseURL, token, claimed.ID, outcome); err != nil {
			observe.Errorf("complete validation %s: %v", claimed.ID, err)
		}
		cancel()
	}
	observe.Infof("validator stopped")
}

func sleepUnlessStopped(ctx context.Context, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// completeWithRetry reports an outcome, retrying network failures and server
// errors a bounded number of times. A refusal (4xx) is final: the run is no
// longer this worker's to report.
func completeWithRetry(ctx context.Context, client *http.Client, baseURL, token, runID string, outcome result) error {
	var err error
	for attempt, delay := 1, time.Second; attempt <= 5; attempt, delay = attempt+1, delay*2 {
		var status int
		status, err = completeOnce(ctx, client, baseURL, token, runID, outcome)
		if err == nil || (status >= 400 && status < 500) {
			return err
		}
		observe.Warnf("report validation %s (attempt %d of 5): %v", runID, attempt, err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w; stopped retrying: %v", err, ctx.Err())
		case <-time.After(delay):
		}
	}
	return err
}

func createBrowserBootstraps(ctx context.Context, client *http.Client, baseURL, token, runID string, nextPaths []string) ([]string, error) {
	payload, err := json.Marshal(map[string]any{"run_id": runID, "next": nextPaths})
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
	// At the deadline the browser run is asked to stop, so it can report the
	// stage it reached and close Chromium, and is killed if it has not
	// exited shortly after.
	// Node starts Chromium and its helpers; they share a process group with
	// it so a stop reaches all of them, and whatever is left when the run
	// ends is killed rather than left behind for every later run to pile on.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGTERM) }
	command.WaitDelay = 15 * time.Second
	command.Stdin = bytes.NewReader(payload)
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"NODE_PATH=" + os.Getenv("NODE_PATH"),
		"PLAYWRIGHT_BROWSERS_PATH=" + os.Getenv("PLAYWRIGHT_BROWSERS_PATH"),
		"SHAUTH_VALIDATION_USERNAME=" + os.Getenv("SHAUTH_VALIDATION_USERNAME"),
		"SHAUTH_VALIDATION_EMAIL=" + os.Getenv("SHAUTH_VALIDATION_EMAIL"),
	}
	// Only stdout carries the result. Warnings Node or Chromium print on
	// stderr must not turn a passing run into an undecodable one; they are
	// kept as context for a failure.
	// Both are bounded: a broken run that floods its output must not
	// exhaust the worker's memory before its deadline.
	stdout := &headBuffer{limit: maximumResultBytes}
	stderr := &tailBuffer{limit: retainedDiagnosticBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	runErr := command.Run()
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	var outcome result
	if stdout.overflowed {
		return result{Status: "failed", Failure: sanitizeJobFailure(fmt.Sprintf("browser result exceeded %d bytes", maximumResultBytes), claimed)}
	}
	if err := decodeSingleJSON(bytes.NewReader(stdout.Bytes()), &outcome); err != nil {
		detail := "decode browser result: " + err.Error()
		if runErr != nil {
			detail = "browser run " + runErr.Error()
		}
		if tail := lastBytes(stderr.String(), 600); tail != "" {
			detail += ": " + tail
		}
		return result{Status: "failed", Failure: sanitizeJobFailure(detail, claimed)}
	}
	if runErr != nil && outcome.Status == "passed" {
		return result{Status: "failed", Failure: sanitizeJobFailure("browser run reported success but exited with "+runErr.Error(), claimed)}
	}
	if outcome.Status != "passed" && outcome.Status != "failed" {
		return result{Status: "failed", Failure: "browser returned an invalid status"}
	}
	outcome.Failure = sanitizeJobFailure(outcome.Failure, claimed)
	return outcome
}

// maximumResultBytes bounds the browser run's result document;
// retainedDiagnosticBytes is how much of its diagnostic output is kept.
const (
	maximumResultBytes      = 64 * 1024
	retainedDiagnosticBytes = 8 * 1024
)

// headBuffer keeps the first limit bytes written and notes anything beyond.
type headBuffer struct {
	bytes.Buffer
	limit      int
	overflowed bool
}

func (buffer *headBuffer) Write(data []byte) (int, error) {
	if room := buffer.limit - buffer.Len(); room < len(data) {
		buffer.overflowed = true
		if room > 0 {
			buffer.Buffer.Write(data[:room])
		}
		return len(data), nil
	}
	return buffer.Buffer.Write(data)
}

// tailBuffer keeps the last limit bytes written, where a failure's cause is.
type tailBuffer struct {
	data  []byte
	limit int
}

func (buffer *tailBuffer) Write(data []byte) (int, error) {
	buffer.data = append(buffer.data, data...)
	if excess := len(buffer.data) - buffer.limit; excess > 0 {
		buffer.data = append(buffer.data[:0], buffer.data[excess:]...)
	}
	return len(data), nil
}

func (buffer *tailBuffer) String() string { return string(buffer.data) }

func sanitizeFailure(value, username string) string {
	secrets := []string{
		username,
		os.Getenv("SHAUTH_VALIDATOR_TOKEN"),
	}
	value = redactCredentialMaterial(value, secrets)
	value = oauthQueryValue.ReplaceAllString(value, "$1[redacted]")
	value = strings.TrimSpace(value)
	value = truncateUTF8(value, 1000)
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
	return sanitizeFailure(value, claimed.ValidationUsername)
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
	if strings.TrimSpace(claimed.ValidationUsername) == "" || strings.TrimSpace(claimed.ValidationEmail) == "" {
		return fmt.Errorf("job validation identity is invalid")
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
	_, err := completeOnce(ctx, client, baseURL, token, runID, outcome)
	return err
}

func completeOnce(ctx context.Context, client *http.Client, baseURL, token, runID string, outcome result) (int, error) {
	payload, err := json.Marshal(outcome)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/internal/validator/jobs/"+runID+"/complete", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return response.StatusCode, fmt.Errorf("complete returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	return response.StatusCode, nil
}

// lastBytes keeps the end of a diagnostic stream, where the cause usually is.
func lastBytes(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	cut := len(value) - limit
	for cut < len(value) && !utf8.RuneStart(value[cut]) {
		cut++
	}
	return value[cut:]
}

// truncateUTF8 bounds value to limit bytes without splitting a character, so
// the result is always valid UTF-8 that PostgreSQL and JSON accept unchanged.
func truncateUTF8(value string, limit int) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}
