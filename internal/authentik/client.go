/*
Copyright 2026 SlashNephy.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package authentik provides access to the authentik API.
package authentik

import (
	"fmt"
	"net/http"
	"net/url"

	api "goauthentik.io/api/v3"
)

// NewAPIClient returns a client for the authentik instance at baseURL that authenticates with the API token.
// baseURL is the root URL of authentik, such as https://auth.example.com; the /api/v3 prefix is appended.
// When httpClient is nil, http.DefaultClient is used.
func NewAPIClient(baseURL, token string, httpClient *http.Client) (*api.APIClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authentik URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("authentik URL must be an absolute http or https URL: %q", baseURL)
	}

	cfg := api.NewConfiguration()
	cfg.Servers = api.ServerConfigurations{{URL: u.JoinPath("api", "v3").String()}}
	cfg.AddDefaultHeader("Authorization", "Bearer "+token)
	cfg.HTTPClient = httpClient

	return api.NewAPIClient(cfg), nil
}
