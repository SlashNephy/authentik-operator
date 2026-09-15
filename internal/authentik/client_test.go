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

package authentik

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAPIClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		basePath string
		wantPath string
	}{
		{
			name:     "root URL without a trailing slash",
			basePath: "",
			wantPath: "/api/v3/admin/version/",
		},
		{
			name:     "root URL with a trailing slash",
			basePath: "/",
			wantPath: "/api/v3/admin/version/",
		},
		{
			name:     "authentik served under a subpath",
			basePath: "/authentik/",
			wantPath: "/authentik/api/v3/admin/version/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotPath, gotAuthorization string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotAuthorization = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version_current":"2026.8.2","version_latest":"2026.8.2","version_latest_valid":true,"build_hash":"","outdated":false,"outpost_outdated":false}`))
			}))
			t.Cleanup(server.Close)

			client, err := NewAPIClient(server.URL+tt.basePath, "secret-token", server.Client())
			require.NoError(t, err)

			version, _, err := client.AdminAPI.AdminVersionRetrieve(t.Context()).Execute()
			require.NoError(t, err)

			assert.Equal(t, tt.wantPath, gotPath)
			assert.Equal(t, "Bearer secret-token", gotAuthorization)
			assert.Equal(t, "2026.8.2", version.VersionCurrent)
		})
	}
}

func TestNewAPIClientInvalidURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		baseURL string
	}{
		{name: "empty", baseURL: ""},
		{name: "relative", baseURL: "auth.example.com"},
		{name: "unsupported scheme", baseURL: "ftp://auth.example.com"},
		{name: "missing host", baseURL: "https://"},
		{name: "malformed", baseURL: "https://auth.example.com:port"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := NewAPIClient(tt.baseURL, "secret-token", nil)
			require.Error(t, err)
			assert.Nil(t, client)
		})
	}
}
