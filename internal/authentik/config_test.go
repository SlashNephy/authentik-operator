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
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   Config
		wantErrs []string
	}{
		{
			name:   "URL and token",
			config: Config{URL: testAuthentikURL, Token: testToken},
		},
		{
			name:   "with a CA file",
			config: Config{URL: testAuthentikURL, Token: testToken, CAFile: "/etc/ssl/authentik.pem"},
		},
		{
			name:     "missing URL and token",
			config:   Config{},
			wantErrs: []string{"AUTHENTIK_URL", "AUTHENTIK_TOKEN"},
		},
		{
			name:     "CA file and insecure together",
			config:   Config{URL: testAuthentikURL, Token: testToken, CAFile: "/etc/ssl/authentik.pem", Insecure: true},
			wantErrs: []string{"--authentik-ca-file and --authentik-insecure"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if len(tt.wantErrs) == 0 {
				require.NoError(t, err)
				return
			}
			for _, wantErr := range tt.wantErrs {
				assert.ErrorContains(t, err, wantErr)
			}
		})
	}
}

func TestNewHTTPClientTLS(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))

	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:   "trusts the server with the CA file",
			config: Config{CAFile: caFile},
		},
		{
			name:   "skips verification when insecure",
			config: Config{Insecure: true},
		},
		{
			name:    "rejects an unknown certificate authority by default",
			config:  Config{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			httpClient, err := NewHTTPClient(&tt.config)
			require.NoError(t, err)

			resp, err := httpClient.Get(server.URL)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		})
	}
}

func TestNewHTTPClientInvalidCAFile(t *testing.T) {
	t.Parallel()

	notPEM := filepath.Join(t.TempDir(), "not.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate"), 0o600))

	tests := []struct {
		name    string
		caFile  string
		wantErr string
	}{
		{name: "missing file", caFile: filepath.Join(t.TempDir(), "missing.pem"), wantErr: "failed to read the authentik CA file"},
		{name: "file without certificates", caFile: notPEM, wantErr: "no PEM certificates found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			httpClient, err := NewHTTPClient(&Config{CAFile: tt.caFile})
			assert.Nil(t, httpClient)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
