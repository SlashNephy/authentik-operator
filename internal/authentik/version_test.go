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
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "goauthentik.io/api/v3"
)

func TestMinorFromClientVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version string
		want    string
		wantErr bool
	}{
		{version: "v3.2026080.2", want: supportedMinor},
		{version: "v3.2026080.0-rc7", want: supportedMinor},
		{version: "v3.2025100.1", want: "2025.10"},
		{version: "v3.1.2", wantErr: true},
		{version: "(devel)", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			t.Parallel()

			got, err := minorFromClientVersion(tt.version)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMinorFromServerVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version string
		want    string
		wantErr bool
	}{
		{version: serverVersion, want: supportedMinor},
		{version: "2026.8.0-rc1", want: supportedMinor},
		{version: "v2026.8.2", want: supportedMinor},
		{version: "2025.10.1", want: "2025.10"},
		{version: "", wantErr: true},
		{version: "latest", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			t.Parallel()

			got, err := minorFromServerVersion(tt.version)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// stubVersionClient returns a fixed version or error.
type stubVersionClient struct {
	version string
	err     error
}

var _ VersionClient = new(stubVersionClient)

func (s *stubVersionClient) GetVersion(context.Context) (*api.Version, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &api.Version{VersionCurrent: s.version}, nil
}

// TestCheckVersion is not parallel because it reads the global version mismatch metric.
func TestCheckVersion(t *testing.T) {
	tests := []struct {
		name         string
		client       *stubVersionClient
		supported    string
		wantMatch    bool
		wantMismatch float64
		wantErr      bool
	}{
		{
			name:         "same minor version with a different patch",
			client:       &stubVersionClient{version: serverVersion},
			supported:    supportedMinor,
			wantMatch:    true,
			wantMismatch: 0,
		},
		{
			name:         "newer minor version",
			client:       &stubVersionClient{version: "2026.10.0"},
			supported:    supportedMinor,
			wantMatch:    false,
			wantMismatch: 1,
		},
		{
			name:      "authentik is unreachable",
			client:    &stubVersionClient{err: errors.New("connection refused")},
			supported: supportedMinor,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := CheckVersion(t.Context(), tt.client, tt.supported)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantMatch, match)
			assert.InDelta(t, tt.wantMismatch, testutil.ToFloat64(versionMismatch.WithLabelValues(tt.client.version, tt.supported)), 0)
		})
	}
}
