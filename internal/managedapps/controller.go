// SPDX-License-Identifier: AGPL-3.0-or-later

// Package managedapps monitors application-owned health endpoints.
package managedapps

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/e6qu/shauth/internal/identity"
)

type ServiceStatus struct {
	Healthy    bool
	StatusCode int
	CheckedAt  time.Time
}

type Controller struct{ client *http.Client }

func New() *Controller { return &Controller{client: &http.Client{Timeout: 10 * time.Second}} }

func (controller *Controller) Status(ctx context.Context, app identity.ManagedApp) (ServiceStatus, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, app.HealthURL, nil)
	if err != nil {
		return ServiceStatus{}, fmt.Errorf("create health request: %w", err)
	}
	response, err := controller.client.Do(request)
	if err != nil {
		return ServiceStatus{}, fmt.Errorf("request health endpoint: %w", err)
	}
	defer response.Body.Close()
	return ServiceStatus{Healthy: response.StatusCode >= 200 && response.StatusCode < 300, StatusCode: response.StatusCode, CheckedAt: time.Now().UTC()}, nil
}
