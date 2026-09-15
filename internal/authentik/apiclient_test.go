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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "goauthentik.io/api/v3"
)

// Values shared by the tests of this package.
const (
	testAuthentikURL = "https://auth.example.com"
	testToken        = "token"
	serverVersion    = "2026.8.2"
	supportedMinor   = "2026.8"
)

// newTestClient returns a client that talks to an httptest server with the handler.
func newTestClient(t *testing.T, handler http.HandlerFunc) *client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	apiClient, err := NewAPIClient(server.URL, testToken, server.Client())
	require.NoError(t, err)
	return &client{api: apiClient}
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// paginatedJSON renders a list response with the given results and next page number (0 for the last page).
func paginatedJSON(results string, next int) string {
	return fmt.Sprintf(`{"pagination":{"next":%d,"previous":0,"count":0,"current":0,"total_pages":0,"start_index":0,"end_index":0},"results":[%s],"autocomplete":{}}`, next, results)
}

func policyJSON(name string) string {
	return fmt.Sprintf(`{"pk":"%s-pk","name":%q,"component":"ak-policy-expression-form","verbose_name":"Expression Policy","verbose_name_plural":"Expression Policies","meta_model_name":"authentik_policies_expression.expressionpolicy","bound_to":0}`, name, name)
}

func TestClientErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		status       int
		body         string
		wantNotFound bool
	}{
		{
			name:         "not found",
			status:       http.StatusNotFound,
			body:         `{"detail":"No Role matches the given query."}`,
			wantNotFound: true,
		},
		{
			name:   "validation error keeps the field messages",
			status: http.StatusBadRequest,
			body:   `{"name":["role with this name already exists."]}`,
		},
		{
			name:   "forbidden",
			status: http.StatusForbidden,
			body:   `{"detail":"You do not have permission to perform this action."}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, tt.status, tt.body)
			})

			role, err := c.GetRole(t.Context(), "role-uuid")
			require.Error(t, err)
			assert.Nil(t, role)
			assert.Equal(t, tt.wantNotFound, errors.Is(err, ErrNotFound))

			var apiErr *APIError
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, "GetRole", apiErr.Operation)
			assert.Equal(t, tt.status, apiErr.StatusCode)
			assert.Equal(t, tt.body, apiErr.Body)
		})
	}
}

func TestClientTransportError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.NotFoundHandler())
	apiClient, err := NewAPIClient(server.URL, testToken, server.Client())
	require.NoError(t, err)
	server.Close()

	_, err = (&client{api: apiClient}).GetRole(t.Context(), "role-uuid")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrNotFound))
	var apiErr *APIError
	assert.False(t, errors.As(err, &apiErr))
}

func TestListRoleObjectPermissionsFollowsPages(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var requests []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.RawQuery)
		mu.Unlock()

		permission := `{"id":%d,"codename":"view_application","model":"application","app_label":"authentik_core","object_pk":"%s","name":"Can view Application","app_label_verbose":"authentik Core","model_verbose":"Application","object_description":null}`
		switch r.URL.Query().Get("page") {
		case "1":
			writeJSON(w, http.StatusOK, paginatedJSON(fmt.Sprintf(permission, 1, "app-1"), 2))
		case "2":
			writeJSON(w, http.StatusOK, paginatedJSON(fmt.Sprintf(permission, 2, "app-2"), 0))
		default:
			writeJSON(w, http.StatusNotFound, `{"detail":"Invalid page."}`)
		}
	})

	permissions, err := c.ListRoleObjectPermissions(t.Context(), "role-uuid")
	require.NoError(t, err)

	objectPKs := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		objectPKs = append(objectPKs, permission.ObjectPk)
	}
	assert.Equal(t, []string{"app-1", "app-2"}, objectPKs)

	require.Len(t, requests, 2)
	for i, rawQuery := range requests {
		assert.Contains(t, rawQuery, fmt.Sprintf("page=%d", i+1))
		assert.Contains(t, rawQuery, "page_size=100")
		assert.Contains(t, rawQuery, "uuid=role-uuid")
	}
}

func TestFindReturnsExactMatchesOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		wantQuery  string
		results    string
		find       func(c *client) ([]string, error)
		wantResult []string
	}{
		{
			name:      "policies are searched and narrowed to the exact name",
			wantQuery: "search=allow",
			results:   strings.Join([]string{policyJSON("allow"), policyJSON("allow-from-office"), policyJSON("Allow")}, ","),
			find: func(c *client) ([]string, error) {
				policies, err := c.FindPoliciesByName(t.Context(), "allow")
				names := make([]string, 0, len(policies))
				for _, policy := range policies {
					names = append(names, policy.Name)
				}
				return names, err
			},
			wantResult: []string{"allow"},
		},
		{
			name:      "roles with a case-variant name are dropped",
			wantQuery: "name=authentik-operator-prod",
			results:   `{"pk":"1","name":"authentik-operator-prod"},{"pk":"2","name":"Authentik-Operator-Prod"}`,
			find: func(c *client) ([]string, error) {
				roles, err := c.FindRolesByName(t.Context(), "authentik-operator-prod")
				pks := make([]string, 0, len(roles))
				for _, role := range roles {
					pks = append(pks, role.Pk)
				}
				return pks, err
			},
			wantResult: []string{"1"},
		},
		{
			name:      "no match returns an empty slice",
			wantQuery: "search=missing",
			results:   policyJSON("missing-policy"),
			find: func(c *client) ([]string, error) {
				policies, err := c.FindPoliciesByName(t.Context(), "missing")
				names := make([]string, 0, len(policies))
				for _, policy := range policies {
					names = append(names, policy.Name)
				}
				return names, err
			},
			wantResult: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotQuery string
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				gotQuery = r.URL.RawQuery
				writeJSON(w, http.StatusOK, paginatedJSON(tt.results, 0))
			})

			got, err := tt.find(c)
			require.NoError(t, err)
			assert.Equal(t, tt.wantResult, got)
			assert.Contains(t, gotQuery, tt.wantQuery)
		})
	}
}

func TestSetOutpostProvidersSendsAnEmptyList(t *testing.T) {
	t.Parallel()

	var gotBody string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		writeJSON(w, http.StatusInternalServerError, `{}`)
	})

	_, err := c.SetOutpostProviders(t.Context(), "outpost-uuid", nil)
	require.Error(t, err)
	assert.JSONEq(t, `{"providers":[]}`, gotBody)
}

// histogramSampleCount returns the number of observations of a histogram series.
func histogramSampleCount(t *testing.T, observer prometheus.Observer) uint64 {
	t.Helper()

	metric, ok := observer.(prometheus.Metric)
	require.True(t, ok)
	var out dto.Metric
	require.NoError(t, metric.Write(&out))
	return out.GetHistogram().GetSampleCount()
}

// TestRequestMetrics is not parallel because it reads the global metric series of GetVersion.
func TestRequestMetrics(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"version_current":"2026.8.2","version_latest":"2026.8.2","version_latest_valid":true,"build_hash":"","outdated":false,"outpost_outdated":false}`)
	})

	okBefore := testutil.ToFloat64(requestsTotal.WithLabelValues("GetVersion", "200"))
	samplesBefore := histogramSampleCount(t, requestDuration.WithLabelValues("GetVersion"))

	version, err := c.GetVersion(t.Context())
	require.NoError(t, err)
	assert.Equal(t, &api.Version{
		VersionCurrent:       serverVersion,
		VersionLatest:        serverVersion,
		VersionLatestValid:   true,
		BuildHash:            "",
		Outdated:             false,
		OutpostOutdated:      false,
		AdditionalProperties: map[string]any{},
	}, version)

	assert.InDelta(t, okBefore+1, testutil.ToFloat64(requestsTotal.WithLabelValues("GetVersion", "200")), 0)
	assert.Equal(t, samplesBefore+1, histogramSampleCount(t, requestDuration.WithLabelValues("GetVersion")))
}
